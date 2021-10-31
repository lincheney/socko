all: socking dnslib.so

socking: socking.c array.c shared.h
	gcc socking.c -o socking

dnslib.so: dnslib.c array.c shared.h
	gcc dnslib.c -o dnslib.so -ldl -fPIC -shared
