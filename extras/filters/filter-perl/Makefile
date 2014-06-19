PROG=   filter-perl
SRCS=   filter_perl.c

CFLAGS+= `perl -MExtUtils::Embed -e ccopts`
LDADD+= `perl -MExtUtils::Embed -e ldopts`

.include <bsd.prog.mk>
