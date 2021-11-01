#define _GNU_SOURCE

#include <netdb.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdio.h>

#include "array.c"
#include "shared.h"

int (*real_getaddrinfo)(const char*, const char*, const void*, void*);

__attribute__((constructor))
static void init(int argc, const char **argv) {
    const char* socking_enabled = getenv("SOCKING_ENABLED");
    if (!socking_enabled || strcmp(socking_enabled, "1") != 0) {
        setenv("SOCKING_ENABLED", "1", 1);

        const char* argv_copy[argc+4];
        argv_copy[0] = "./socking";
        argv_copy[1] = "-p127.0.0.1:8888";
        argv_copy[2] = "-l/home/qianli/Documents/repos/socking/dnslib.so";
        for (int i = 0; i < argc; i++) {
            argv_copy[i+3] = argv[i];
        }
        argv_copy[argc+3] = NULL;

        execv(argv_copy[0], (char* const*)argv_copy);
        perror("Cannot run socking");
    }
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
}

#define cmp_fn(key, value) (strcmp((key), (value)) == 0)
ARRAY_TYPE(AddressArray, char*, char*, cmp_fn);
AddressArray addresses = {0, 0, NULL};

extern int getaddrinfo (const char *restrict name,
			const char *restrict service,
			const struct addrinfo *restrict req,
			struct addrinfo **restrict result) {
    if (real_getaddrinfo) {
        /* printf("getaddrinfo(%s, %s)\n", name, service); */

        if (name) {
            uint16_t port = 0;
            if (service) {
                struct servent* serv = getservbyname(service, NULL);
                if (serv) {
                    port = serv->s_port;
                } else {
                    port = htons(atoi(service ? service : "0"));
                }
            }

            uint16_t name_len = strlen(name) + 1;
            int index = AddressArray_find(&addresses, name);
            if (index < 0) {
                index = AddressArray_append(&addresses, strdup(name));
            }

            addrinfo_data address_data = {addresses.data[index], name_len, port};

            struct addrinfo* address = malloc(sizeof(struct addrinfo));
            address->ai_flags = 0;
            address->ai_family = AF_INET6;
            address->ai_socktype = SOCK_STREAM;
            address->ai_protocol = IPPROTO_TCP;
            address->ai_addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6* addr6 = malloc(address->ai_addrlen);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = port;
            addr6->sin6_flowinfo = 0;
            memcpy(addr6->sin6_addr.s6_addr, &address_data, sizeof(address_data));
            addr6->sin6_scope_id = SCOPE_ID;
            address->ai_addr = (struct sockaddr*)addr6;
            address->ai_canonname = NULL;
            address->ai_next = NULL;
            *result = address;

            return 0;
        }


        return real_getaddrinfo(name, service, req, result);
    } else {
        return EAI_FAIL;
    }
}
