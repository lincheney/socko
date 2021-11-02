#define _GNU_SOURCE

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <poll.h>
#include <errno.h>
#include <netdb.h>
#include <dlfcn.h>
#include <unistd.h>

#include "array.c"
#include "shared.h"

#define WORD_SIZE sizeof(size_t)
#define ALIGNED_SIZE(x) ((x) + (x) % -WORD_SIZE)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define POLLFD_SIZE ALIGNED_SIZE(sizeof(struct pollfd))

unsigned int ptrace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

// socks proxy address
uint32_t proxy_host;
uint16_t proxy_port;

typedef struct user_regs_struct registers;

// register state, so we can restore it
typedef struct {
    registers old_regs;
    size_t rip;
} register_state;

// ptrace state machine
typedef struct {
    enum {
        START,
        POST_CONNECT,
        MAKE_IPV4_SOCKET,
        MAKE_MMAP,
        CONNECT_IPV4_SOCKET,
        POST_CONNECT_IPV4,
        POST_MMAP,
        SEND_HANDSHAKE_POLL,
        SEND_HANDSHAKE,
        RECV_HANDSHAKE_POLL_FIRST,
        RECV_HANDSHAKE_POLL,
        RECV_HANDSHAKE,
        POST_RECV_HANDSHAKE,
        RECV_ADDRESS_POLL_FIRST,
        RECV_ADDRESS_POLL,
        RECV_ADDRESS,
        POST_RECV_ADDRESS,
        DONE,
    } next;

    int sock_fd;
    int is_ipv6;
    int address_len;
    char address[512];
    char original_address[256];
    size_t original_addr_len;
    register_state reg_state;
    void* mmap_addr;
    void* mmap_addr_after_pollfd;
    int to_receive;
    int in_syscall;
} state;

// lookup table for processes
typedef struct {
    pid_t pid;
    state state;
} process_state;

#define process_cmp_fn(key, value) ((key) == (value.pid))
ARRAY_TYPE(ProcessArray, process_state, pid_t, process_cmp_fn);
ProcessArray processes = {0, 0, NULL};


int (*real_getaddrinfo)(const char*, const char*, const void*, void*);
int hijack_dns = 0;

// lookup table for addresses
#define cmp_fn(key, value) (strcmp((key), (value)) == 0)
ARRAY_TYPE(AddressArray, char*, char*, cmp_fn);
AddressArray addresses = {0, 0, NULL};


extern int getaddrinfo(const char *restrict name,
                        const char *restrict service,
                        const struct addrinfo *restrict req,
                        struct addrinfo **restrict result) {

    if (hijack_dns && name) {
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

    if (real_getaddrinfo) {
        return real_getaddrinfo(name, service, req, result);
    }
    return EAI_FAIL;
}

#include <sys/uio.h>
void get_data(pid_t pid, void* addr, void* buffer, int count) {
    struct iovec local_iov = {buffer, count};
    struct iovec remote_iov = {(void*)addr, count};
    process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

void* put_data(pid_t pid, void* addr, void* buffer, int count) {
    struct iovec local_iov = {buffer, count};
    struct iovec remote_iov = {(void*)addr, count};
    process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    return addr + count;
}

register_state syscall_wrapper(pid_t pid, size_t syscall, size_t arg0, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5) {
    registers regs, old_regs;

    // get initial registers
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    old_regs = regs;

    // populate new registers
    regs.rax = syscall;
    regs.rdi = arg0;
    regs.rsi = arg1;
    regs.rdx = arg2;
    regs.r10 = arg3;
    regs.r8 = arg4;
    regs.r9 = arg5;

    // get initial RIP
    size_t rip = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);

    // set the registers
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    // set RIP
    ptrace(PTRACE_POKEDATA, pid, regs.rip, 0x050f); //syscall

    register_state state = {old_regs, rip};
    return state;
}

size_t post_syscall(pid_t pid, register_state state) {
    registers regs;
    // restore RIP
    ptrace(PTRACE_POKETEXT, pid, state.old_regs.rip, state.rip); //syscall
    // return
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    // restore registers
    ptrace(PTRACE_SETREGS, pid, NULL, &state.old_regs);
    return regs.rax;
}

void set_syscall_return_code(pid_t pid, int rc) {
    registers regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rax = rc;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

state execute_state_machine(state state, pid_t pid, struct user_regs_struct regs) {
    int rc;

    switch (state.next) {
        case START: {
            state.is_ipv6 = 0;

            state.sock_fd = regs.rdi;
            void* addr_ptr = (void*)regs.rsi;
            state.original_addr_len = regs.rdx;

            get_data(pid, (void*)regs.rsi, state.original_address, state.original_addr_len);
            struct sockaddr* address_buffer = alloca(state.original_addr_len);
            memcpy(address_buffer, state.original_address, state.original_addr_len);

            state.next = POST_CONNECT;
            switch (address_buffer->sa_family) {
                case AF_INET: {
                    struct sockaddr_in* address = (void*)address_buffer;
                    state.address_len = 1+4+2;
                    state.address[0] = 0x01;
                    *(uint32_t*)(state.address+1) = address->sin_addr.s_addr;
                    *(uint16_t*)(state.address+state.address_len-2) = address->sin_port;

                    address->sin_addr.s_addr = proxy_host;
                    address->sin_port = htons(proxy_port);
                    put_data(pid, addr_ptr, address_buffer, state.original_addr_len);
                    break;
                }

                case AF_INET6: {
                    state.is_ipv6 = 1;
                    struct sockaddr_in6* address = (void*)address_buffer;

                    if (address->sin6_scope_id == SCOPE_ID) {
                        // hijack
                        addrinfo_data *data = (void*)address->sin6_addr.s6_addr;
                        state.address_len = 1 + 1 + data->len - 1 + 2;
                        state.address[0] = 0x03;
                        state.address[1] = data->len - 1;
                        get_data(pid, data->name_ptr, state.address+2, data->len-1);

                    } else {
                        state.address_len = 1+16+2;
                        state.address[0] = 0x04;
                        memcpy(state.address+1, address->sin6_addr.s6_addr, 16);
                    }
                    *(uint16_t*)(state.address+state.address_len-2) = address->sin6_port;

                    // force the connect to fail
                    address->sin6_port = 0;
                    put_data(pid, addr_ptr, address_buffer, state.original_addr_len);
                    break;
                }
                default:
                    state.next = DONE;
                    break;
            }
            break;
        }

        case POST_CONNECT: {
            /* printf("connect() == %i\n", regs.rax); */

            // restore the original address, since connect() is meant to be const
            put_data(pid, (void*)state.reg_state.old_regs.rsi, state.original_address, state.original_addr_len);

            if (state.is_ipv6) {
                state.reg_state = syscall_wrapper(pid, SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
                state.next = MAKE_IPV4_SOCKET;
            } else if (regs.rax < 0) {
                set_syscall_return_code(pid, regs.rax);
                state.next = DONE;
            } else {
                if (state.mmap_addr) {
                    state.next = SEND_HANDSHAKE_POLL;
                } else {
                    state.next = MAKE_MMAP;
                }
                return execute_state_machine(state, pid, regs);
            }
            break;
        }

        case MAKE_IPV4_SOCKET: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("socket() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.reg_state = syscall_wrapper(pid, SYS_dup2, rc, state.sock_fd, 0, 0, 0, 0);
            state.next = CONNECT_IPV4_SOCKET;
            break;
        }

        case CONNECT_IPV4_SOCKET: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("dup2() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }
            struct sockaddr_in address;
            address.sin_family = AF_INET;
            address.sin_port = htons(proxy_port);
            address.sin_addr.s_addr = proxy_host;
            size_t addr_ptr = state.reg_state.old_regs.rsi;

            put_data(pid, (void*)addr_ptr, &address, sizeof(address));
            state.reg_state = syscall_wrapper(pid, SYS_connect, state.sock_fd, addr_ptr, sizeof(struct sockaddr_in), 0, 0, 0);
            state.next = POST_CONNECT_IPV4;
            break;
        }

        case POST_CONNECT_IPV4: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("connect() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            if (state.mmap_addr) {
                state.next = SEND_HANDSHAKE_POLL;
            } else {
                state.next = MAKE_MMAP;
            }
            return execute_state_machine(state, pid, regs);
        }

        case MAKE_MMAP: {
            state.reg_state = syscall_wrapper(pid, SYS_mmap, 0, 1024, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
            state.next = POST_MMAP;
            break;
        }

        case POST_MMAP: {
            state.mmap_addr = (void*)post_syscall(pid, state.reg_state);
            if (state.mmap_addr == MAP_FAILED) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.mmap_addr_after_pollfd = state.mmap_addr + POLLFD_SIZE;
            state.next = SEND_HANDSHAKE_POLL;
            break;
        }

        case SEND_HANDSHAKE_POLL: {
            struct pollfd pollfd = {state.sock_fd, POLLOUT};
            put_data(pid, state.mmap_addr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, (size_t)state.mmap_addr, 1, -1, 0, 0, 0);
            state.next = SEND_HANDSHAKE;
            break;
        }

        case SEND_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("poll() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            // replace with sendto
            char request[1024] =
                "\x05" // version
                "\x01" // no. auth
                "\x00" // noauth
                "\x05" // version
                "\x01" // command
                "\x00" // reserved
                ;
            memcpy(request+6, state.address, state.address_len);
            put_data(pid, state.mmap_addr_after_pollfd, request, sizeof(request));
            state.reg_state = syscall_wrapper(pid, SYS_sendto, state.sock_fd, (size_t)state.mmap_addr_after_pollfd, 6+state.address_len, 0, 0, 0);
            state.to_receive = 6;
            state.next = RECV_HANDSHAKE_POLL_FIRST;
            break;
        }

        case RECV_HANDSHAKE_POLL_FIRST:
            rc = post_syscall(pid, state.reg_state);
            /* printf("sendto/poll() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

        case RECV_HANDSHAKE_POLL: {
            struct pollfd pollfd = {state.sock_fd, POLLIN};
            put_data(pid, state.mmap_addr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, (size_t)state.mmap_addr, 1, -1, 0, 0, 0);
            state.next = RECV_HANDSHAKE;
            break;
        }

        case RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("poll() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, (size_t)state.mmap_addr_after_pollfd+6-state.to_receive, state.to_receive, 0, 0, 0);
            state.next = POST_RECV_HANDSHAKE;
            break;
        }

        case POST_RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("recvfrom() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.to_receive -= rc;
            if (rc == 0) {
                set_syscall_return_code(pid, -ECONNRESET);
                state.next = DONE;
            } else if (state.to_receive == 0) {
                char buffer[6];
                get_data(pid, state.mmap_addr_after_pollfd, buffer, sizeof(buffer));
                if (buffer[0] != 0x05 || buffer[1] != 0x00 || buffer[2] != 0x05 || buffer[3] != 0x00 || buffer[4] != 0x00) {
                    set_syscall_return_code(pid, -ECONNRESET);
                    state.next = DONE;
                    goto finish_state;
                }
                int to_read;
                switch (buffer[5]) {
                    case 0x01:
                        state.to_receive = 4+2;
                        break;
                    case 0x03:
                        state.to_receive = 1;
                        break;
                    case 0x04:
                        state.to_receive = 16+2;
                        break;
                    default:
                        set_syscall_return_code(pid, -ECONNRESET);
                        state.next = DONE;
                        goto finish_state;
                }
                state.next = RECV_ADDRESS_POLL_FIRST;
                return execute_state_machine(state, pid, regs);
            } else {
                state.next = RECV_HANDSHAKE_POLL;
                return execute_state_machine(state, pid, regs);
            }
            break;
        }

        case RECV_ADDRESS_POLL:
            rc = post_syscall(pid, state.reg_state);
            /* printf("recvfrom() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

        case RECV_ADDRESS_POLL_FIRST: {
            struct pollfd pollfd = {state.sock_fd, POLLIN};
            put_data(pid, state.mmap_addr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, (size_t)state.mmap_addr, 1, -1, 0, 0, 0);
            state.next = RECV_ADDRESS;
            break;
        }

        case RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("poll() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            // drop the data
            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, (size_t)state.mmap_addr_after_pollfd, state.to_receive, 0, 0, 0);
            state.next = POST_RECV_ADDRESS;
            break;
        }

        case POST_RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            /* printf("recvfrom() == %i\n", rc); */
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.to_receive -= rc;
            if (rc == 0) {
                set_syscall_return_code(pid, -ECONNRESET);
                state.next = DONE;
            } else if (state.to_receive == 0) {
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                state.next = DONE;
            } else {
                state.next = RECV_ADDRESS_POLL;
            }
            break;
        }

    }

finish_state:
    if (state.next == DONE) {
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    } else {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
    return state;
}

void handle_process(int index, pid_t pid, registers regs) {
    state oldstate = processes.data[index].state;
    state newstate = execute_state_machine(oldstate, pid, regs);
    processes.data[index].state = newstate;
}

#include <sys/prctl.h>
#include <seccomp.h>

__attribute__((constructor))
static void init(int argc, const char **argv) {
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");

    const char* socking_enabled = getenv("SOCKING_ENABLED");
    if (socking_enabled && strcmp(socking_enabled, "1") == 0) {
        // we are already being ptraced ...
        hijack_dns = 1;
        return;
    }

    // ... otherwise we need to fork and ptrace

    const char* socking_proxy = getenv("SOCKING_PROXY");
    if (!socking_proxy) {
        /* dprintf(2, "Error: $SOCKING_PROXY has not been set\n"); */
        return;
    }
    char* proxy = strdup(socking_proxy);
    char* host = strtok(proxy, ":");
    char* port = strtok(NULL, "");
    if (!host || !port || sscanf(port, "%u", &proxy_port) != 1 || inet_pton(AF_INET, host, &proxy_host) != 1) {
        dprintf(2, "Error: invalid $SOCKING_PROXY: %s\n", socking_proxy);
        return;
    }
    free(proxy);

    // get filename of this shared lib
    Dl_info info;
    if (dladdr(init, &info) == 0) {
        dprintf(2, "Error: Could not determine path to shared library\n");
        return;
    }

    pid_t tracer_pid = getpid();

    pid_t child = fork();
    if (child < 0) {
        perror("Failed to fork");
        exit(1);
    }

    if (child == 0) {
        // this should already be LD_PRELOAD-ed, right?
        /* char ld_preload[1024] = "LD_PRELOAD="; */
        /* strncat(ld_preload, info.dli_fname, sizeof(ld_preload)-1); */
        /* strncat(ld_preload, ":", sizeof(ld_preload)-1); */
        /* if (!getenv("LD_PRELOAD")) { */
            /* strncat(ld_preload, getenv("LD_PRELOAD"), sizeof(ld_preload)-1); */
        /* } */

        int env_length;
        for (env_length = 0; environ[env_length]; env_length++) ;
        char* new_env[env_length+3];
        memcpy(new_env, environ, sizeof(char*)*env_length);
        new_env[env_length] = "SOCKING_ENABLED=1";
        /* new_env[env_length+1] = ld_preload; */
        new_env[env_length+2] = NULL;

        scmp_filter_ctx ctx;
        ctx = seccomp_init(SCMP_ACT_ALLOW);
        seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), SCMP_SYS(connect), 0);
        seccomp_load(ctx);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        // must use execvpe, setenv/putenv doesn't work in some cases
        execvpe(argv[0], (char* const*)argv, new_env);
        // unreachable
        perror(argv[0]);
        exit(1);
    }

    int rc = 0;
    int first = 1;
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, 0);

        if (pid < 0 && errno == ECHILD) {
            break;
        } else if (pid < 0) {
            perror("Error: waitpid() failed");
            exit(1);
        }

        if (WIFEXITED(status)) {
            if (pid == child) {
                rc = WEXITSTATUS(status);
            }

            // process exited
            int index = ProcessArray_find(&processes, pid);
            if (index >= 0) {
                ProcessArray_delete(&processes, index);
            }
            continue;
        }

        int signal = (status >> 8) & 0xff;
        int event = (status >> 16) & 0xff;
        int is_syscall = signal == (0x80 | SIGTRAP);
        signal &= ~0x80;

        /* int signal = WSTOPSIG(status); */
        int process_index = ProcessArray_find(&processes, pid);
        if (process_index < 0) {
            if (signal != SIGSTOP) {
                dprintf(2, "Error: tracee not stopped\n");
                exit(1);
            }

            // first time seeing process
            process_state item = {pid, {DONE,}};
            item.state.mmap_addr = 0;
            item.state.in_syscall = 0;
            process_index = ProcessArray_append(&processes, item);
            ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_options);
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }

        int ptrace_request = PTRACE_CONT;
        if (processes.data[process_index].state.next != DONE) {
            ptrace_request = PTRACE_SYSCALL;
        }

        if (!event && !is_syscall) {
            ptrace(ptrace_request, pid, NULL, signal);
            continue;
        } else if (event && event != PTRACE_EVENT_SECCOMP) {
            ptrace(ptrace_request, pid, NULL, 0);
            continue;
        }

        /*
         * connect() is the only syscall that we will get a SECCOMP event for
         * what will happen is this:
         * - the first connect() will get a seccomp event and a syscall exit
         * - subsequent connect() will get a seccomp event, a syscall enter and syscall exit
         * - other syscalls will get a syscall enter and a syscall exit
         * except for that very first connect(), we want only the exit for all other syscalls (including the second connect())
        */

        if (event && processes.data[process_index].state.next != DONE) {
            // skip non-first connect() seccomp events
            ptrace(PTRACE_SYSCALL, pid, NULL, 0);
            continue;
        }

        processes.data[process_index].state.in_syscall ^= 1;
        if (event) {
            processes.data[process_index].state.next = START;
        } else if (processes.data[process_index].state.in_syscall) {
            ptrace(PTRACE_SYSCALL, pid, NULL, 0);
            continue;
        }

        registers regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        handle_process(process_index, pid, regs);
    }
    exit(rc);
}
