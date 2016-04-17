CFLAGS=	 -Wall -g
LDFLAGS= -g
LIBS=	-lpcap

all: dhcprl

clean:
	-rm dhcprl.o dhcprl

dhcprl: dhcprl.o
	${CC} ${LDFLAGS} -o $@ dhcprl.o ${LIBS}

dhcprl.o: dhcprl.c Makefile
	${CC} ${CFLAGS} -c -o $@ dhcprl.c
