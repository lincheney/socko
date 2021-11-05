BINARY=socko
LIBRARY=sockolib.so

all: ${LIBRARY}

# ${BINARY}: socko.c array.c shared.h
	# gcc socko.c -o $@

${LIBRARY}: array.h socko.c
	gcc socko.c -o $@ -ldl -lseccomp -fPIC -shared
