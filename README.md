libtls tests
============

This is independent version of `test_tls.c` from libusual repo.

To compile, first create synlink to libtls sources:

    $ ln -s /usr/src/lib/libtls .
    $ gmake

It also has standalone cert parser `xparse`.  It can be run
on either ordinary .crt / .pem files but also `*_cert.gz`
files from [https://scans.io/]():

- [https://scans.io/study/sonar.ssl]()
- [https://scans.io/study/sonar.moressl]()

