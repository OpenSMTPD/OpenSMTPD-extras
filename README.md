# OpenSMTPD-extras
This is the mirror of the official repository of OpenSMTPD addons

## THIS REPOSITORY IS ARCHIVED

With OpenSMTPD 7.6 the table protocol was changed, and existing tables were splitted off to a different repository.  Please upgrade to the right table, i.e.:

 - table-ldap → https://github.com/opensmtpd/table-ldap
 - table-mysql → https://github.com/opensmtpd/table-mysql
 - table-passwd → https://github.com/opensmtpd/table-passwd
 - table-postgres → https://github.com/opensmtpd/table-postgres
 - table-redis → https://github.com/opensmtpd/table-redis
 - table-socketmap → https://github.com/opensmtpd/table-socketmap
 - table-sqlite → https://github.com/opensmtpd/table-sqlite


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
