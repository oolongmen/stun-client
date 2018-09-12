.PHONY: all clean debug

CFLAGS=-DNDEBUG

all: stun-test udp-echo-server udp-test

debug: CFLAGS= 
debug: all

stun-test: stun.h stun.cpp
	${CXX} -o $@ ${CFLAGS} $^

udp-echo-server: udp-echo-server.cpp
	${CXX} -o $@ ${CFLAGS} $^

udp-test: udp-test.cpp
	${CXX} -o $@ ${CFLAGS} $^

clean:
	rm -rf stun-test udp-echo-server udp-test
