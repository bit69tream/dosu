CFLAGS = -std=c11 -Wall -Wextra -Werror -pedantic -O2
LDFLAGS = -lcrypt -lbsd
PREFIX = /usr/

dosu: dosu.c
	${CC} -o $@ $^ ${CFLAGS} ${LDFLAGS}

install: dosu
	chown root:root dosu
	chmod o-r dosu
	chmod a-w dosu
	cp dosu ${PREFIX}/bin/dosu
	chmod u+s ${PREFIX}/bin/dosu
