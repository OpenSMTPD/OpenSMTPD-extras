SUBDIRS=

if HAVE_LDAP
SUBDIRS+=	table-ldap
endif

if HAVE_POSTGRES
SUBDIRS+=	table-postgres
endif

SUBDIRS+=	table-python

if HAVE_MYSQL
SUBDIRS+=	table-mysql
endif

if HAVE_REDIS
SUBDIRS+=	table-redis
endif

if HAVE_SOCKETMAP
SUBDIRS+=	table-socketmap
endif
