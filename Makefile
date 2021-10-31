all: socking dnslib.so

socking: socking.c array.c
	gcc socking.c -o socking

dnslib.so: dnslib.c array.c
	gcc dnslib.c -o dnslib.so -ldl -fPIC -shared
