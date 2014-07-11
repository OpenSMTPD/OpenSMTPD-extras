Preliminary note
================

This package provides pluggable backends to the OpenSMTPD server.

For more information: [http://www.opensmtpd.org/](http://www.opensmtpd.org/)

How to build, configure and use OpenSMTPD extras
================================================

Dependencies
------------

XXX


Get the source
--------------

    git clone -b portable git://github.com/OpenSMTPD/opensmtpd-extras.git

or

    wget http://www.opensmtpd.org/archives/opensmtpd-extras-portable.tar.gz
    tar xzvf opensmtpd-extras-portable.tar.gz


Build
-----

    cd opensmtpd-extras
    ./bootstrap  # Only if you build from git sources
    ./configure
    make

### Special notes for FreeBSD/DragonFlyBSD/Mac OS X:

Please launch configure with special directive about libevent directory:

#### FreeBSD:

    ./configure --with-libevent-dir=/usr/local

#### DragonFlyBSD:

    ./configure --with-libevent-dir=/usr/pkg

#### Mac OS X:

    ./configure --with-libevent-dir=/opt/local
    make CFLAGS="-DBIND_8_COMPAT=1"


Install
-------

    sudo make install


