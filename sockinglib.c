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
int hijack = 0;

__attribute__((constructor))
static void init(int argc, const char **argv) {
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");

    const char* socking_enabled = getenv("SOCKING_ENABLED");
    if (!socking_enabled || strcmp(socking_enabled, "1") != 0) {
        // get filename of this shared lib
        Dl_info info;
        if (dladdr(init, &info) == 0) {
            dprintf(2, "Could not determine path to shared library\n");
            return;
        }

        const char* socking_proxy = getenv("SOCKING_PROXY");
        if (!socking_proxy) {
            dprintf(2, "$SOCKING_PROXY has not been set\n");
            return;
        }

        const char* socking_path = getenv("SOCKING_PATH");
        if (!socking_path) {
            dprintf(2, "$SOCKING_PATH has not been set\n");
            return;
        }

        const char* argv_copy[argc+7];
        argv_copy[0] = socking_path;
        argv_copy[1] = "-p";
        argv_copy[2] = socking_proxy;
        argv_copy[3] = "-l";
        argv_copy[4] = info.dli_fname;
        for (int i = 0; i < argc; i++) {
            argv_copy[i+5] = argv[i];
        }
        argv_copy[argc+5] = NULL;

        setenv("SOCKING_ENABLED", "1", 1);
        execv(argv_copy[0], (char* const*)argv_copy);

        setenv("SOCKING_ENABLED", "0", 1);
        perror("Cannot run socking");
        return;
    }
    hijack = 1;
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

        if (hijack && name) {
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
