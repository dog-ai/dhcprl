CFLAGS=	-Wall -g
LDFLAGS=-g

all: build/dhcprl

clean:
	rm -r build

build/dhcprl: build/dhcprl.o
	${CC} ${LDFLAGS} -o $@ build/dhcprl.o

build/dhcprl.o: src/dhcprl.c
	mkdir -p build
	${CC} ${CFLAGS} -c -o $@ src/dhcprl.c
