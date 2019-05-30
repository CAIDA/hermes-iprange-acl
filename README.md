# Hermes IP Range ACL Middleware

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
Default is to deny all remote access when no ACLs are present.

## Installing

This middleware requires the pytricia and py2-ipaddress packages. These
should be installed automatically by the setup.py script.

```
git clone git@github.com:caida/hermes-iprange-acl
cd hermes-iprange-acl/
python setup.py install
```

## Configuration
To use this middleware, add `iprange_acl` to your proxy server pipeline
immediately after your regular auth middleware(s) (such as `keystone_auth`
or `tempauth`).

You should also add the following section to the bottom of your proxy
server configuration file:

```
[filter:iprange_acl]
use = egg:iprange_acl#iprange_acl
always_allow = <your org IP range>		# optional
```

The `always_allow` configuration option allows you to specify an IP range
that is always allowed to access any container, regardless of the ACLs
specified on that container. This can be used to provide global access to
users within your organisation, whilst still maintaining a default deny
unless otherwise specified policy for everyone else.

Specific IP Range ACLs themselves are specified by attaching metadata to the
container that you want the ACL to apply to. The metadata key must begin
with the phrase `allowed-iprange-`, e.g.
`allowed-iprange-example=192.168.200.0/24`. Multiple prefixes may be specified
by using multiple metadata entries, but remember that each entry must have a
unique key.

Note that any containers with no ACL metadata will default to denying anyone
access to them, unless the `ipacl-default` metadata field is attached to the
container with the value set to `allowed` or the user is coming from the IP
range described in the `always_allow` config option.
