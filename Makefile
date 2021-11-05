LIBRARY=sockolib.so

all: ${LIBRARY}

${LIBRARY}: array.h socko.c
	gcc socko.c -o $@ -ldl -lseccomp -fPIC -shared -Wall
