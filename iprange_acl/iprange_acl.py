# Copyright (c) 2014 OpenStack Foundation
#
# This code is forked from the IP Whitelist middleware published by
# the OpenStack Foundation.

# Modifications are
#    Copyright 2019 The Regents of the University of California.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import socket
import pytricia
import ipaddress
from swift.proxy.controllers.base import get_container_info
from swift.common.utils import get_logger, get_remote_client
from swift.common.swob import Request, Response

class IPRangeACLMiddleware(object):
    """
    Swift middleware for controlling access to containers based on IP.

    Based on the IP Whitelist middleware published at
    https://wiki.openstack.org/wiki/Customizing_Object_Storage_(Swift)_Middleware

    Extended to allow the specification of IP ranges using an IP prefix.
    Also supports IPv6 ACLs.

    Allowed ranges are specified by adding metadata to the container which
    begins with the string 'allowed-iprange-', e.g.
    allowed-iprange-example=192.168.200.0/24

    For containers without any allowed range metadata, you can set a default
    policy using the 'ipacl-default' metadata field. To deny all access
    attempts until an ACL is added to the container, set this to 'denied'.
    To allow all access attempts until an ACL is added, set this to 'allowed'.
    Default is to deny access when no ACLs are present.

    You can additionally configure an IP range that will be allowed access
    to all containers, regardless of any policy that is attached as metadata
    by setting the 'always_allow' config option in /etc/swift/proxy-server.conf
    with your preferred IP range.

    Requires: py2-ipaddress, pytricia
    """

    def __init__(self, app, conf, logger=None):
        self.app = app

        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='iprange_acl')

        self.deny_message = conf.get('deny_message', "Access Denied (IP Range ACL)")
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.default_range = conf.get('always_allow', "127.0.0.1")

    def __call__(self, env, start_response):
        req = Request(env)

        try:
            version, account, container, obj = req.split_path(1, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if container is None:
            return self.app(env, start_response)

        if env.get('swift.authorize_override', False):
            return self.app(env, start_response)

        container_info = get_container_info(req.environ, self.app,
                swift_source='IPRangeACLMiddleware')

        remote_ip = get_remote_client(req)

        #self.logger.debug("Remote IP: %(remote_ip)s", {
        #        'remote_ip': remote_ip})

        meta = container_info['meta']
        allowed = set()
        default = "denied"
        for k, v in meta.iteritems():
            # Each allowed range must have a unique meta-data key, but
            # the key must begin with 'allowed-iprange-'
            if k.startswith('allowed-iprange-') and len(v) > 0:
                allowed.add(v)

            # This key is used to set the default access policy in
            # cases where no ACLs are present in the meta-data.
            if k == "ipacl-default":
                default = v

        # XXX Could probably condense this into one tree, but not sure
        # whether Pytricia is OK with mixing IPv4 and IPv6 prefixes.
        self.pyt = pytricia.PyTricia(32)
        self.pyt6 = pytricia.PyTricia(128)

        # If there are no IP range ACLs in the meta-data and the
        # default policy is "allowed", then we can grant access.
        if len(allowed) == 0 and default == "allowed":
            return self.app(env, start_response)
        else:
            #self.logger.debug("Allowed IP ranges: %(range)s",
            #        {'range': allowed})

            for pref in allowed:

                if ':' in pref:
                    try:
                        addrcheck = ipaddress.IPv6Network(unicode(pref), False)
                    except ipaddress.AddressValueError:
                        self.logger.debug("iprange_acl -- skipping invalid IP prefix: %(pref)s", {'pref': pref})
                        continue
                    self.pyt6[pref] = "allowed"
                else:
                    try:
                        addrcheck = ipaddress.IPv4Network(unicode(pref), False)
                    except ipaddress.AddressValueError:
                        self.logger.debug("iprange_acl -- skipping invalid IP prefix: %(pref)s", {'pref': pref})
                        continue

                    self.pyt[pref] = "allowed"

        # Always allow our own IP, otherwise we could lock ourselves out from
        # the container!
        if ':' in self.local_ip:
            self.pyt6[self.local_ip] = "allowed"
        else:
            self.pyt[self.local_ip] = "allowed"

        if ':' in self.default_range:
            try:
                addrcheck = ipaddress.IPv6Network(unicode(self.default_range), \
                        False)
            except ipaddress.AddressValueError:
                self.logger.debug("Invalid always_allow prefix for IPv6: %s" \
                        % (self.default_range))
            else:
                self.pyt6[self.default_range] = "allowed"
        else:
            try:
                addrcheck = ipaddress.IPv4Network(unicode(self.default_range), \
                        False)
            except ipaddress.AddressValueError:
                self.logger.debug("Invalid always_allow prefix for IPv4: %s" \
                        % (self.default_range))
            else:
                self.pyt[self.default_range] = "allowed"

        if ':' in remote_ip:
            status = self.pyt6.get(remote_ip)
        else:
            status = self.pyt.get(remote_ip)

        if status == "allowed":
            return self.app(env, start_response)

        self.logger.debug("IP %(remote_ip)s denied access to Account %(account)s, Container %(container)s", locals())
        return Response(status=403, body=self.deny_message, request=req)(env,
                start_response)

def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def iprange_acl(app):
        return IPRangeACLMiddleware(app, conf)
    return iprange_acl


# vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
