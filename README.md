# OpenSMTPD-extras
This is the mirror of the official repository of OpenSMTPD addons

# THIS REPOSITORY IS IN MAINTENANCE, ONLY ACCEPTING BUG FIXES AND MINOR UPDATES.

# How to install
First, you need to clone the repository:

    $ git clone https://github.com/OpenSMTPD/OpenSMTPD-extras.git

Secondly, you need to bootstrap the repository, some dependencies (autotools, libtool) may be needed:

    $ sh bootstrap

Then, you need to configure what add-ons you want to install, for example:

    $ ./configure --libexecdir=/usr/libexec/opensmtpd --with-table-mysql --with-filter-stub --with-queue-ram


Finally build and install:

    $ make
    # make install

The addons will be installed in /usr/libexec/opensmtpd where OpenSMTPD can find them.
