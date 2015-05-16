PROG=	filter-perl
SRCS=	filter_perl.c
NOMAN=	noman

CFLAGS+= `perl -MExtUtils::Embed -e ccopts`
LDADD+= `perl -MExtUtils::Embed -e ldopts`

uninstall:
	rm -f ${BINDIR}/filter-perl

.include <bsd.prog.mk>
