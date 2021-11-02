#ifndef __SHARED_H__
#define __SHARED_H__

typedef struct {
    void* name_ptr;
    uint16_t len;
    uint16_t port;
} addrinfo_data;

#define SCOPE_ID ((uint32_t)0xffffff)

#endif
