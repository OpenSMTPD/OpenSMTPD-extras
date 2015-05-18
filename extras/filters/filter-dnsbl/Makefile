ASRDIR=		${.CURDIR}/../../asr

NEED_ASR!=	grep -q event_asr_run /usr/include/event.h && echo No || echo Yes

PROG=	filter-dnsbl
SRCS=	filter_dnsbl.c
MAN=	filter-dnsbl.8

.if ${NEED_ASR} == "Yes"
CFLAGS+=	-I${ASRDIR}
SRCS+=	asr.c
SRCS+=	asr_debug.c
SRCS+=	asr_private.h
SRCS+=	asr_utils.c
SRCS+=	getaddrinfo.c
SRCS+=	getaddrinfo_async.c
SRCS+=	gethostnamadr.c
SRCS+=	gethostnamadr_async.c
SRCS+=	getnameinfo.c
SRCS+=	getnameinfo_async.c
SRCS+=	getnetnamadr.c
SRCS+=	getnetnamadr_async.c
SRCS+=	getrrsetbyname.c
SRCS+=	getrrsetbyname_async.c
SRCS+=	res_debug.c
SRCS+=	res_init.c
SRCS+=	res_mkquery.c
SRCS+=	res_query.c
SRCS+=	res_search_async.c
SRCS+=	res_send.c
SRCS+=	res_send_async.c
SRCS+=	sethostent.c
SRCS+=	event_asr_run.c
.endif

uninstall:
	rm -f /usr/share/man/man8/filter-dnsbl.8
	rm -f ${BINDIR}/filter-dnsbl

.include <bsd.prog.mk>
