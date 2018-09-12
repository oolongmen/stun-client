# stun
utility tool to test nat type.

# Build

```
make clean
make

# to enable debug
make debug
```

# stun-test

```
stun-test 0.1

Usage: stun-test [Options]

Options:
 -h                       print this help
 -i, --ip [str]           local ip
 -p, --port [num]         local port
 -s, --sname [str]        stun server name or ip
 -o, --sport [num]        stun server port

./stun-test
./stun-test -p 51111
./stun-test -p 51111 -s stun.xten.com -o 3478

```
