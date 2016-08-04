CFLAGS=	 -Wall -g
LDFLAGS= -g

all: dhcprl

clean:
	-rm dhcprl.o dhcprl

dhcprl: dhcprl.o
	${CC} ${LDFLAGS} -o $@ dhcprl.o ${LIBS}

dhcprl.o: src/dhcprl.c Makefile
	${CC} ${CFLAGS} -c -o $@ src/dhcprl.c
