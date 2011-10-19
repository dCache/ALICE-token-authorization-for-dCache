ALICE authorization provider for dCache
=======================================

Selectio of authorization providers that allows dCache to be used as
an ALICE storage element.

About the provider
------------------

[dCache] is a distributed storage system frequently used in the
[Worldwide LHC Computing Grid][WLCG], high energy physics, photon
sciences, and a couple of other communities.

[ALICE] is one of the LHC experiments. ALICE heavily relies on the
[xrootd data access protocol][xrootd]. The xrootd protocol is
supported by dCache out of the box.

ALICE relies on a proprietary authorization scheme using
cryptographically signed authorization tokens. This project provides
plugins for dCache 2.0 and newer. The plugins implement various
versions of the ALICE authorization scheme. Using the plugins, dCache
can be used as an ALICE storage element.


Compilation
-----------

To compile the provider one first needs to import the official
dcache.jar into the local Maven repository. Download the dCache
tarball from www.dcache.org and extract dcache.jar. Then import the
file:

    mvn install:install-file \
         -Dfile=path/to/dcache.jar \
         -DgroupId=org.dcache -DartifactId=dcache -Dversion=2.0.0 \
         -Dpackaging=jar


After that the provider can be compiled with:

    mvn package


Installation
------------

To install the provider you first setup a plugin directory for
dCache. Add the following line to your dcache.conf

    dcache.java.classpath=/usr/local/share/dcache/plugins/*

and create the /usr/local/share/dcache/plugins/ directory.

Then upload the provider jar, xrootd-authz-plugin-alice-VERSION.jar,
to the plugin directory.


Loading a plugin
----------------

To load a plugin in the xrootd door, add the following line to
dcache.conf:

    xrootdAuthzPlugin=NAME

where NAME is the plugin name: The provider contains (or will
contain) multiple plugins.

Plugin: alice-token-1
---------------------

This is currently the only plugin included, although more plugins will
be added.

The plugin is nearly identical to the token authorization plugin used
in earlier releases of dCache. The only difference is that stat and
statx optionally accept an authorization token. The original plugin
ignored the authorization even if present.

To identify the keystore, define the following in dcache.conf:

    xrootdAuthzKeystore=/etc/dcache/keystore

No default is currently defined.

A possible keystore file is:

    KEY VO:*   PRIVKEY:/etc/dcache/privkey.der  PUBKEY:/etc/dcache/pubkey.der

With privkey.der and pubkey.der being the ALICE keypair.


Authors
-------

The code was originally written by Martin Radicke and sponsored by
DESY. It has since been maintained by Gerd Behrmann and sponsored by
NDGF.

[ALICE]:  http://aliweb.cern.ch/
[dCache]: http://www.dcache.org/
[xrootd]: http://xrootd.slac.stanford.edu/
[WLCG]: http://lcg.web.cern.ch/lcg/