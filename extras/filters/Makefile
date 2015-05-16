.include <bsd.own.mk>

SUBDIR	+=	filter-clamav
SUBDIR	+=	filter-dkim-signer
SUBDIR	+=	filter-dnsbl
#SUBDIR	+=	filter-lua
SUBDIR	+=	filter-monkey
SUBDIR	+=	filter-pause
SUBDIR	+=	filter-perl
SUBDIR	+=	filter-python
SUBDIR	+=	filter-regex
SUBDIR	+=	filter-spamassassin
SUBDIR	+=	filter-stub
SUBDIR	+=	filter-trace
SUBDIR	+=	filter-void

uninstall:
	cd filter-clamav && make uninstall
	cd filter-dkim-signer && make uninstall
	cd filter-dnsbl && make uninstall
	#cd filter-lua && make uninstall
	cd filter-monkey && make uninstall
	cd filter-pause && make uninstall
	cd filter-perl && make uninstall
	cd filter-python && make uninstall
	cd filter-regex && make uninstall
	cd filter-spamassassin && make uninstall
	cd filter-stub && make uninstall
	cd filter-trace && make uninstall
	cd filter-void && make uninstall

.include <bsd.subdir.mk>
