PROG=	filter-dkim-signer
SRCS=	filter_dkim_signer.c

LDADD+=	-lcrypto
DPADD+=	${LIBCRYPTO}

NOMAN=	noman

uninstall:
	rm -f ${BINDIR}/filter-dkim-signer

.include<bsd.prog.mk>
