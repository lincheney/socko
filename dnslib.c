#define _GNU_SOURCE

#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

int (*real_getaddrinfo)(const char*, const char*, const void*, void*);

__attribute__((constructor))
static void init() {
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
}

struct {
    size_t length;
    size_t capacity;
    char** names;
} addresses = {0, 0, NULL};

void* get_or_insert_address(const char* name, int name_len) {
    // try to find existing address
    for (int i = 0; i < addresses.length; i++) {
        if (strncmp(name, addresses.names[i], name_len) == 0) {
            return addresses.names[i];
        }
    }

    // resize if not enough space
    if (addresses.length >= addresses.capacity) {
        if (addresses.capacity == 0) {
            addresses.capacity = 4;
        } else {
            addresses.capacity *= 2;
        }
        addresses.names = realloc(addresses.names, addresses.capacity*sizeof(char*));
    }
    // make our own copy of the name
    char* name_copy = malloc(name_len);
    strncpy(name_copy, name, name_len);
    // insert the new name
    addresses.names[addresses.length] = name_copy;
    addresses.length += 1;
    return name_copy;
}

extern int getaddrinfo (const char *restrict name,
			const char *restrict service,
			const struct addrinfo *restrict req,
			struct addrinfo **restrict result) {
    if (real_getaddrinfo) {
        printf("getaddrinfo(%s, %s)\n", name, service);

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
            struct {
                void* name_ptr;
                uint16_t len;
                uint16_t port;
            } address_data = {get_or_insert_address(name, name_len), name_len, port};

            struct addrinfo* address = malloc(sizeof(struct addrinfo));
            address->ai_flags = 0;
            address->ai_family = AF_INET6;
            address->ai_socktype = SOCK_STREAM;
            address->ai_protocol = IPPROTO_TCP;
            address->ai_addrlen = sizeof(struct sockaddr_in6);
            struct sockaddr_in6* addr6 = malloc(address->ai_addrlen);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = 0xffff;
            addr6->sin6_flowinfo = 0;
            memcpy(addr6->sin6_addr.s6_addr, &address_data, sizeof(address_data));
            addr6->sin6_scope_id = 0;
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
