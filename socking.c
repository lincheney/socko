#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <poll.h>
#include <errno.h>

#include "array.c"
#include "shared.h"

#define WORD_SIZE sizeof(size_t)
#define ALIGNED_SIZE(x) ((x) + (x) % -WORD_SIZE)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define POLLFD_SIZE ALIGNED_SIZE(sizeof(struct pollfd))

void get_data(pid_t child, size_t addr, char* buffer, int count) {
    size_t* _buffer = (size_t*)buffer;
    for (int i = 0; i < count; i++) {
        _buffer[i] = ptrace(PTRACE_PEEKTEXT, child, addr + i*WORD_SIZE, NULL);
    }
}

size_t put_data(pid_t child, size_t addr, char* buffer, int count) {
    size_t* _buffer = (size_t*)buffer;
    for (int i = 0; i < count; i++) {
        ptrace(PTRACE_POKEDATA, child, addr + i*WORD_SIZE, _buffer[i]);
    }
    return addr + count*WORD_SIZE;
}

typedef struct user_regs_struct registers;

typedef struct {
    registers old_regs;
    size_t rip;
} register_state;

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
    register_state reg_state;
    size_t mmap_addr;
    size_t mmap_addr_after_pollfd;
    int to_receive;
} state;

state execute_state_machine(state state, pid_t pid, struct user_regs_struct regs) {
    int rc;

    switch (state.next) {
        case START: {
            state.is_ipv6 = 0;

            state.sock_fd = regs.rdi;
            size_t addr_ptr = regs.rsi;
            size_t addr_len = regs.rdx;

            char* address_buffer = alloca(ALIGNED_SIZE(addr_len));
            get_data(pid, regs.rsi, address_buffer, ALIGNED_SIZE(addr_len)/WORD_SIZE);

            int family = ((struct sockaddr*)address_buffer)->sa_family;

            // replace with 127.0.0.1:8888
            state.next = POST_CONNECT;
            switch (family) {
                case AF_INET: {
                    struct sockaddr_in* address = (struct sockaddr_in*)address_buffer;
                    state.address_len = 1+4+2;
                    state.address[0] = 0x01;
                    *(uint32_t*)(state.address+1) = address->sin_addr.s_addr;
                    *(uint16_t*)(state.address+state.address_len-2) = address->sin_port;

                    inet_pton(family, "127.0.0.1", &(address->sin_addr));
                    address->sin_port = htons(8888);
                    put_data(pid, addr_ptr, address_buffer, ALIGNED_SIZE(addr_len)/WORD_SIZE);
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
                        get_data(pid, (size_t)(data->name_ptr), state.address+2, ALIGNED_SIZE(data->len-1)/WORD_SIZE);
                        *(uint16_t*)(state.address+state.address_len-2) = data->port;

                    } else {
                        state.address_len = 1+16+2;
                        state.address[0] = 0x04;
                        memcpy(state.address+1, address->sin6_addr.s6_addr, 16);
                        *(uint16_t*)(state.address+state.address_len-2) = address->sin6_port;
                    }

                    // force the connect to fail
                    address->sin6_port = 0;
                    put_data(pid, addr_ptr, address_buffer, ALIGNED_SIZE(addr_len)/WORD_SIZE);
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
            char* address_buffer = alloca(ALIGNED_SIZE(sizeof(struct sockaddr_in)));
            struct sockaddr_in* address = (void*)address_buffer;
            address->sin_family = AF_INET;
            address->sin_port = htons(8888);
            inet_pton(AF_INET, "127.0.0.1", &(address->sin_addr));
            size_t addr_ptr = state.reg_state.old_regs.rsi;

            put_data(pid, addr_ptr,address_buffer, ALIGNED_SIZE(sizeof(struct sockaddr_in))/WORD_SIZE);
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
            state.mmap_addr = post_syscall(pid, state.reg_state);
            if ((void*)state.mmap_addr == MAP_FAILED) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.mmap_addr_after_pollfd = state.mmap_addr + POLLFD_SIZE;
            state.next = SEND_HANDSHAKE_POLL;
            break;
        }

        case SEND_HANDSHAKE_POLL: {
            char fds[POLLFD_SIZE];
            struct pollfd* pollfd = (struct pollfd*)fds;
            pollfd->fd = state.sock_fd;
            pollfd->events = POLLOUT;
            put_data(pid, state.mmap_addr, fds, POLLFD_SIZE/WORD_SIZE);

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.mmap_addr, 1, -1, 0, 0, 0);
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
            put_data(pid, state.mmap_addr_after_pollfd, request, sizeof(request)/WORD_SIZE);
            state.reg_state = syscall_wrapper(pid, SYS_sendto, state.sock_fd, state.mmap_addr_after_pollfd, 6+state.address_len, 0, 0, 0);
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
            char fds[POLLFD_SIZE];
            struct pollfd* pollfd = (struct pollfd*)fds;
            pollfd->fd = state.sock_fd;
            pollfd->events = POLLIN;
            put_data(pid, state.mmap_addr, fds, POLLFD_SIZE/WORD_SIZE);

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.mmap_addr, 1, -1, 0, 0, 0);
            state.next = RECV_HANDSHAKE;
            break;
        }

        case RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, state.mmap_addr_after_pollfd+6-state.to_receive, state.to_receive, 0, 0, 0);
            state.next = POST_RECV_HANDSHAKE;
            break;
        }

        case POST_RECV_HANDSHAKE: {
            rc = post_syscall(pid, state.reg_state);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.to_receive -= rc;
            if (rc == 0) {
                set_syscall_return_code(pid, ECONNRESET);
                state.next = DONE;
            } else if (state.to_receive == 0) {
                char buffer[WORD_SIZE];
                get_data(pid, state.mmap_addr_after_pollfd, buffer, sizeof(buffer)/WORD_SIZE);
                if (buffer[0] != 0x05 || buffer[1] != 0x00 || buffer[2] != 0x05 || buffer[3] != 0x00 || buffer[4] != 0x00) {
                    set_syscall_return_code(pid, ECONNRESET);
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
                        set_syscall_return_code(pid, ECONNRESET);
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
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

        case RECV_ADDRESS_POLL_FIRST: {
            char fds[POLLFD_SIZE];
            struct pollfd* pollfd = (struct pollfd*)fds;
            pollfd->fd = state.sock_fd;
            pollfd->events = POLLIN;
            put_data(pid, state.mmap_addr, fds, POLLFD_SIZE/WORD_SIZE);

            state.reg_state = syscall_wrapper(pid, SYS_poll, state.mmap_addr, 1, -1, 0, 0, 0);
            state.next = RECV_ADDRESS;
            break;
        }

        case RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            // drop the data
            state.reg_state = syscall_wrapper(pid, SYS_recvfrom, state.sock_fd, state.mmap_addr_after_pollfd, state.to_receive, 0, 0, 0);
            state.next = POST_RECV_ADDRESS;
            break;
        }

        case POST_RECV_ADDRESS: {
            rc = post_syscall(pid, state.reg_state);
            if (rc < 0) {
                set_syscall_return_code(pid, rc);
                state.next = DONE;
                break;
            }

            state.to_receive -= rc;
            if (rc == 0) {
                set_syscall_return_code(pid, ECONNRESET);
                state.next = DONE;
            } else if (state.to_receive == 0) {
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                state.next = DONE;
            } else {
                state.next = RECV_ADDRESS_POLL;
            }
            break;
        }

        case DONE: {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            return state;
        }

    }

finish_state:
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    return state;
}

typedef struct {
    pid_t pid;
    state state;
} process_state;

#define cmp_fn(key, value) ((key) == (value.pid))
ARRAY_TYPE(ProcessArray, process_state, pid_t, cmp_fn);
ProcessArray processes = {0, 0, NULL};

void handle_process(int index, pid_t pid, registers regs) {
    state oldstate = processes.data[index].state;
    state newstate = execute_state_machine(oldstate, pid, regs);
    processes.data[index].state = newstate;
}

unsigned int ptrace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;

void print_help(int fd, char** argv) {
    dprintf(fd,
"%s -p PROXY:PORT -l DNSLIB -- COMMAND [ARGS...]\n\
\n\
Tunnel COMMAND through the PROXY on PORT.\n\
\n\
DNSLIB will be used to intercept DNS lookups via LD_PRELOAD.\n\
\n\
Both -p and -l are required arguments.\
", argv[0]);
}

int main(int argc, char** argv) {
    char* proxy = NULL;
    char* lib = NULL;
    int flag;
    opterr = 0;
    while ((flag = getopt(argc, argv, "+hp:l:")) != -1) {
        switch (flag) {
            case 'p':
                proxy = optarg;
                break;
            case 'l':
                lib = optarg;
                break;
            case '?':
                print_help(2, argv);
                return 1;
            case 'h':
                print_help(1, argv);
                return 0;
        }
    }
    if (! proxy || ! lib) {
        print_help(2, argv);
        return 1;
    }
    if (optind == argc) {
        dprintf(2, "Error: no commands given");
        return 1;
    }

    pid_t tracer_pid = getpid();

    pid_t child = fork();
    if (child == 0) {
        char ld_preload[1024] = "";
        strncat(ld_preload, lib, sizeof(ld_preload)-1);
        strncat(ld_preload, ":", sizeof(ld_preload)-1);
        strncat(ld_preload, getenv("LD_PRELOAD"), sizeof(ld_preload)-1);
        setenv("LD_PRELOAD", ld_preload, 1);

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[optind], argv+optind);
        // unreachable
        perror(argv[optind]);
        return 1;
    }

    int rc = 0;
    int first = 1;
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, 0);

        if (pid < 0 && errno == ECHILD) {
            break;
        } else if (pid < 0) {
            perror("waitpid() failed");
            return 1;
        }

        if (WIFEXITED(status)) {
            rc = WEXITSTATUS(status);
            // process exited
            int index = ProcessArray_find(&processes, pid);
            if (index >= 0) {
                ProcessArray_delete(&processes, index);
            }
            continue;
        }

        if (first) {
            if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
                perror("not stopped");
                return 1;
            }
            ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_options);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            first = 0;
        }
        registers regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        int index = -1;
        switch (regs.orig_rax) {
            case SYS_connect:
                index = ProcessArray_find(&processes, pid);
                if (index < 0) {
                    // first time seeing process
                    process_state item = {pid, {START,}};
                    item.state.mmap_addr = 0;
                    index = ProcessArray_append(&processes, item);
                } else if (processes.data[index].state.next == DONE) {
                    processes.data[index].state.next = START;
                }
                handle_process(index, pid, regs);
                break;
            default:
                index = ProcessArray_find(&processes, pid);
                if (index >= 0) {
                    handle_process(index, pid, regs);
                } else {
                    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                }
                break;
        }
    }
    return rc;
}
