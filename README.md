ALICE authorization provider for dCache
=======================================

Selection of authorization plugins for xrootd4j that allows dCache to
be used as an ALICE storage element.

About the provider
------------------

[dCache] is a distributed storage system frequently used in the
[Worldwide LHC Computing Grid][WLCG], high energy physics, photon
sciences, and other communities. 

[ALICE] is one of the LHC experiments. ALICE heavily relies on the
[xrootd data access protocol][xrootd]. The xrootd protocol is
supported by dCache out of the box and implemented in the [xrootd4j]
library.

ALICE relies on a proprietary authorization scheme using
cryptographically signed authorization tokens. This project provides
plugins for dCache 2.0 and newer. The plugins implement various
versions of the ALICE authorization scheme. Using the plugins, dCache
can be used as an ALICE storage element.


Compilation
-----------

The provider is compiled with:

    mvn package


Using the plugin with xrootd4j standalone
-----------------------------------------

Untar the tarball:

    cd /tmp
    tar xzf xrootd4j-authz-plugin-alice-VERSION.tar.gz

Add the directory in which the tarball was unpacked (not the directory
contained in the tarball) to the plugin search path:

    java -Dlog=debug -DxrootdAuthzKeystore=/etc/dcache/xrootd/keystore \
         -jar xrootd4j-standalone-1.0.0-jar-with-dependencies.jar \
         --plugins /tmp/ \
         --authz alice-token-1


Using the plugin with dCache
----------------------------

The plugin ships with dCache 2.1 and can be enabled by adding the
following line to dcache.conf:

    xrootdAuthzPlugin=alice-token-1

We are currently considering to backport xrootd4j to dCache 1.9.12 and
will include the Alice plugin.

Plugin: alice-token-1
---------------------

This is currently the only plugin included, although more plugins will
be added.

The plugin is nearly identical to the token authorization plugin used
in earlier releases of dCache. The only difference is that stat and
statx optionally accept an authorization token. The original plugin
ignored the authorization token even if present.

To identify the keystore, define the following parameter (in
dcache.conf for dCache or on the command line of xrootd4j):

    xrootdAuthzKeystore=/etc/dcache/keystore

A possible keystore file is:

    KEY VO:*   PRIVKEY:/etc/dcache/privkey.der  PUBKEY:/etc/dcache/pubkey.der

With privkey.der and pubkey.der being the ALICE xrootd keypair.


Authors
-------

The code was originally written by Martin Radicke and sponsored by
[DESY]. It has since been maintained by Thomas Zangerl and Gerd
Behrmann, both sponsored by [NDGF].

[ALICE]:  http://aliweb.cern.ch/
[dCache]: http://www.dcache.org/
[xrootd]: http://xrootd.slac.stanford.edu/
[xrootd4j]: http://github.com/gbehrmann/xrootd4j
[WLCG]: http://lcg.web.cern.ch/lcg/
[NDGF]: http://www.ndgf.org/
[DESY]: http://www.desy.de/
