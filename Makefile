BINARY=socking
LIBRARY=sockinglib.so

all: ${BINARY} ${LIBRARY}

${BINARY}: socking.c array.c shared.h
	gcc socking.c -o $@

${LIBRARY}: sockinglib.c array.c shared.h
	gcc sockinglib.c -o $@ -ldl -fPIC -shared
