BINARY=socking
LIBRARY=sockinglib.so

all: ${LIBRARY}

# ${BINARY}: socking.c array.c shared.h
	# gcc socking.c -o $@

${LIBRARY}: array.c shared.h socking.c
	gcc socking.c -o $@ -ldl -fPIC -shared
