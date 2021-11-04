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
#include <fcntl.h>

#include "array.c"
#include "shared.h"

#define WORD_SIZE sizeof(size_t)
#define ALIGNED_SIZE(x) ((x) + (x) % -WORD_SIZE)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define POLLFD_SIZE ALIGNED_SIZE(sizeof(struct pollfd))
#define SYSCALL 0x050f
typedef uint16_t instruction_t;

/* #define DEBUG(...) dprintf(2, __VA_ARGS__) */
#define DEBUG(...)

unsigned int ptrace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

// socks proxy address
uint32_t proxy_host;
uint16_t proxy_port;

typedef struct user_regs_struct registers;

// register state, so we can restore it
typedef struct {
    registers old_regs;
    instruction_t rip;
} register_state;

// ptrace state machine
typedef struct {
    enum {
        START,
        CONNECT,
        POST_CONNECT,
        MAKE_IPV4_SOCKET,
        FCNTL_IPV4_SOCKET,
        DUP_IPV4_SOCKET,
        CONNECT_IPV4_SOCKET,
        POST_CONNECT_IPV4,
        SEND_HANDSHAKE_POLL,
        SEND_HANDSHAKE,
        POST_SEND_HANDSHAKE,
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
    int is_tcp;
    int fcntl;

    char buffer[512];
    int buffer_start;
    int buffer_len;

    char original_address[256];
    size_t original_addr_len;
    size_t original_addr_ptr;

    register_state reg_state;
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
    register_state state;
    registers regs;

    // get initial registers
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    state.old_regs = regs;

    // populate new registers
    regs.orig_rax = syscall;
    regs.rax = syscall;
    regs.rdi = arg0;
    regs.rsi = arg1;
    regs.rdx = arg2;
    regs.r10 = arg3;
    regs.r8 = arg4;
    regs.r9 = arg5;
    regs.rip -= sizeof(instruction_t);

    // get initial RIP
    get_data(pid, (void*)regs.rip, &state.rip, sizeof(instruction_t));
    if (state.rip != SYSCALL) {
        // set RIP
        instruction_t newrip = 0x050f;
        put_data(pid, (void*)regs.rip, &newrip, sizeof(instruction_t));
    }

    // set the registers
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    return state;
}

size_t post_syscall(pid_t pid, register_state state) {
    registers regs;
    // restore RIP
    if (state.rip != SYSCALL) {
        put_data(pid, (void*)state.old_regs.rip, &state.rip, sizeof(instruction_t));
    }
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
            state.is_tcp = 0;

            state.sock_fd = regs.rdi;
            state.original_addr_ptr = regs.rsi;
            state.original_addr_len = regs.rdx;
            get_data(pid, (void*)state.original_addr_ptr, state.original_address, state.original_addr_len);

            int len = sizeof(uint32_t);
            put_data(pid, (void*)state.original_addr_ptr+len, &len, sizeof(len));
            state.reg_state = syscall_wrapper(pid, SYS_getsockopt, state.sock_fd, SOL_SOCKET, SO_TYPE, state.original_addr_ptr, state.original_addr_ptr+len, 0);
            state.next = CONNECT;
            break;
        }

        case CONNECT: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: getsockopt() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            // get the sock type
            uint32_t type = 0;
            get_data(pid, (void*)state.original_addr_ptr, &type, sizeof(uint32_t));
            // then restore the original address
            put_data(pid, (void*)state.original_addr_ptr, state.original_address, state.original_addr_len);

            state.next = POST_CONNECT;
            if (type == SOCK_STREAM) {
                state.is_tcp = 1;

                struct sockaddr* address_buffer = alloca(state.original_addr_len);
                memcpy(address_buffer, state.original_address, state.original_addr_len);

                state.buffer_start = 0;
                memcpy(state.buffer,
                    "\x05" // version
                    "\x01" // no. auth
                    "\x00" // noauth
                    "\x05" // version
                    "\x01" // command
                    "\x00" // reserved
                    , 6);
                state.buffer_len = 6;

                state.next = POST_CONNECT;
                switch (address_buffer->sa_family) {
                    case AF_INET: {
                        struct sockaddr_in* address = (void*)address_buffer;
                        state.buffer_len += 1 + sizeof(uint32_t) + sizeof(uint16_t);
                        state.buffer[6] = 0x01;
                        memcpy(state.buffer+6+1, &address->sin_addr.s_addr, sizeof(uint32_t));
                        memcpy(state.buffer+6+1+sizeof(uint32_t), &address->sin_port, sizeof(uint16_t));

                        address->sin_addr.s_addr = proxy_host;
                        address->sin_port = htons(proxy_port);
                        put_data(pid, (void*)state.original_addr_ptr, address_buffer, state.original_addr_len);
                        break;
                    }

                    case AF_INET6: {
                        struct sockaddr_in6* address = (void*)address_buffer;

                        if (address->sin6_scope_id == SCOPE_ID) {
                            // hijack
                            addrinfo_data *data = (void*)address->sin6_addr.s6_addr;
                            state.buffer_len += 2 + (data->len-1) + sizeof(uint16_t);
                            state.buffer[6] = 0x03;
                            state.buffer[7] = data->len-1;
                            get_data(pid, data->name_ptr, state.buffer+6+2, data->len-1);
                            memcpy(state.buffer+6+2+(data->len-1), &address->sin6_port, sizeof(uint16_t));

                        } else {
                            state.buffer_len += 1 + 16 + sizeof(uint16_t);
                            state.buffer[6] = 0x04;
                            memcpy(state.buffer+6+1, &address->sin6_addr.s6_addr, 16);
                            memcpy(state.buffer+6+1+16, &address->sin6_port, sizeof(uint16_t));
                        }

                        // need to remake as an ipv4 socket
                        state.reg_state = syscall_wrapper(pid, SYS_fcntl, state.sock_fd, F_GETFL, 0, 0, 0, 0);
                        state.next = MAKE_IPV4_SOCKET;
                        return execute_state_machine(state, pid, regs);
                    }
                }
            }

            // resume the connect call
            regs = state.reg_state.old_regs;
            state.reg_state = syscall_wrapper(pid, regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
            break;
        }

        case POST_CONNECT: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: connect() == %i\n", pid, rc);
            if ((rc < 0 && rc != -EINPROGRESS) || !state.is_tcp) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            if (regs.rax < 0) {
                set_syscall_return_code(pid, regs.rax);
                state.next = DONE;
            } else {
                state.next = SEND_HANDSHAKE_POLL;
                return execute_state_machine(state, pid, regs);
            }
            break;
        }

        case MAKE_IPV4_SOCKET: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: fcntl() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.fcntl = rc;
            state.reg_state = syscall_wrapper(pid, SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
            state.next = DUP_IPV4_SOCKET;
            break;
        }

        case FCNTL_IPV4_SOCKET: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: socket() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.reg_state = syscall_wrapper(pid, SYS_fcntl, state.sock_fd, F_SETFL, state.fcntl, 0, 0, 0);
            state.next = DUP_IPV4_SOCKET;
            break;
        }

        case DUP_IPV4_SOCKET: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: fcntl() == %i\n", pid, rc);
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
            DEBUG("%i: dup2() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }
            struct sockaddr_in address;
            address.sin_family = AF_INET;
            address.sin_port = htons(proxy_port);
            address.sin_addr.s_addr = proxy_host;

            put_data(pid, (void*)state.original_addr_ptr, &address, sizeof(address));
            state.reg_state = syscall_wrapper(pid, SYS_connect, state.sock_fd, state.original_addr_ptr, sizeof(struct sockaddr_in), 0, 0, 0);
            state.next = POST_CONNECT_IPV4;
            break;
        }

        case POST_CONNECT_IPV4: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: connect() == %i\n", pid, rc);
            if (rc < 0 && rc != -EINPROGRESS) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.next = SEND_HANDSHAKE_POLL;
            return execute_state_machine(state, pid, regs);
        }

        case SEND_HANDSHAKE_POLL: {
            struct pollfd pollfd = {state.sock_fd, POLLOUT};
            put_data(pid, (void*)state.original_addr_ptr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.original_addr_ptr, 1, -1, 0, 0, 0);
            state.next = SEND_HANDSHAKE;
            break;
        }

        case SEND_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: poll() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            int len = min(state.original_addr_len, state.buffer_len);
            // replace with sendto
            put_data(pid, (void*)state.original_addr_ptr, state.buffer+state.buffer_start, len);
            state.reg_state = syscall_wrapper(pid, SYS_sendto, state.sock_fd, (size_t)state.original_addr_ptr, len, 0, 0, 0);
            state.next = POST_SEND_HANDSHAKE;
            break;
        }

        case POST_SEND_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: sendto() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }
            state.buffer_start += rc;
            state.buffer_len -= rc;
            if (state.buffer_len > 0) {
                state.next = SEND_HANDSHAKE_POLL;
                return execute_state_machine(state, pid, regs);
            }
            state.next = RECV_HANDSHAKE_POLL;
            state.buffer_start = 0;
            state.buffer_len = 6;
            return execute_state_machine(state, pid, regs);
        }

        case RECV_HANDSHAKE_POLL: {
            struct pollfd pollfd = {state.sock_fd, POLLIN};
            put_data(pid, (void*)state.original_addr_ptr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.original_addr_ptr, 1, -1, 0, 0, 0);
            state.next = RECV_HANDSHAKE;
            break;
        }

        case RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: poll() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            int len = min(state.original_addr_len, state.buffer_len);
            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, state.original_addr_ptr, len, 0, 0, 0);
            state.next = POST_RECV_HANDSHAKE;
            break;
        }

        case POST_RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: handshake: recvfrom() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            if (rc == 0) {
                set_syscall_return_code(pid, -ECONNRESET);
                state.next = DONE;
                break;
            }

            get_data(pid, (void*)state.original_addr_ptr, state.buffer+state.buffer_start, rc);
            state.buffer_len -= rc;
            state.buffer_start += rc;

            if (state.buffer_len == 0) {
                if (state.buffer[0] != 0x05 || state.buffer[1] != 0x00 || state.buffer[2] != 0x05 || state.buffer[3] != 0x00 || state.buffer[4] != 0x00) {
                    set_syscall_return_code(pid, -ECONNRESET);
                    state.next = DONE;
                    break;
                }
                switch (state.buffer[5]) {
                    case 0x01:
                        state.buffer_len = 4+2;
                        break;
                    case 0x03:
                        state.buffer_len = 1;
                        break;
                    case 0x04:
                        state.buffer_len = 16+2;
                        break;
                    default:
                        set_syscall_return_code(pid, -ECONNRESET);
                        state.next = DONE;
                        break;
                }
                state.buffer_start = 0;
                state.next = RECV_ADDRESS_POLL;
                return execute_state_machine(state, pid, regs);
            } else {
                state.next = RECV_HANDSHAKE_POLL;
                return execute_state_machine(state, pid, regs);
            }
            break;
        }

        case RECV_ADDRESS_POLL: {
            struct pollfd pollfd = {state.sock_fd, POLLIN};
            put_data(pid, (void*)state.original_addr_ptr, &pollfd, sizeof(pollfd));

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.original_addr_ptr, 1, -1, 0, 0, 0);
            state.next = RECV_ADDRESS;
            break;
        }

        case RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: poll() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            // drop the data
            int len = min(state.original_addr_len, state.buffer_len);
            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, state.original_addr_ptr, len, 0, 0, 0);
            state.next = POST_RECV_ADDRESS;
            break;
        }

        case POST_RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            DEBUG("%i: address: recvfrom() == %i\n", pid, rc);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            if (rc == 0) {
                set_syscall_return_code(pid, -ECONNRESET);
                state.next = DONE;
                break;
            }

            get_data(pid, (void*)state.original_addr_ptr, state.buffer+state.buffer_start, rc);
            state.buffer_len -= rc;
            state.buffer_start += rc;

            if (state.buffer_len == 0) {
                set_syscall_return_code(pid, 0);
                state.next = DONE;
            } else {
                state.next = RECV_ADDRESS_POLL;
            }
            break;
        }

    }

    if (state.next == DONE) {
        // restore the original address, since connect() is meant to be const
        put_data(pid, (void*)state.original_addr_ptr, state.original_address, state.original_addr_len);

        ptrace(PTRACE_CONT, pid, NULL, 0);
    } else {
        ptrace(PTRACE_SYSCALL, pid, NULL, 0);
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
