all: socking dnslib.so

socking: socking.c
	gcc socking.c -o socking

dnslib.so: dnslib.c
	gcc dnslib.c -o dnslib.so -ldl -fPIC -shared
