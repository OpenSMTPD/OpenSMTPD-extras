# OpenSMTPD-extras
This is the mirror of the official repository of OpenSMTPD addons

# How to install
First, you need to clone the repository matching your OpenSMTPD version.
As of now, only "master" and "portable" are supported, tags will be issued for specific versions later.

    $ git clone https://github.com/OpenSMTPD/OpenSMTPD-extras.git -b master

or

    $ git clone https://github.com/OpenSMTPD/OpenSMTPD-extras.git -b portable
    

Secondly, you need to bootstrap the repository, some dependencies (autotools, libtool) may be needed:

    $ sh bootstrap

Then, you need to configure what add-ons you want to install, for example:

    $ ./configure --libexecdir=/usr/libexec/opensmtpd --with-table-mysql --with-filter-stub --with-queue-ram


Finally build and install:

    $ make
    # make install

The addons will be installed in /usr/libexec/opensmtpd where OpenSMTPD can find them.
