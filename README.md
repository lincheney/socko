# socko

This is another SOCKS 5 proxifier, in the same vein as
[proxychains-ng](https://github.com/rofl0r/proxychains-ng/) or
[graftcp](https://github.com/hmgle/graftcp).
It forces applications to route their traffic through a specified SOCKS 5 proxy
(e.g. if they don't natively support SOCKS 5 proxies through environment variables, command line switches etc).

It combines techniques from both `proxychains-ng` and `graftcp`
in that it can hijack `connect` *syscalls* using `ptrace`,
but also handle DNS by hijacking `getaddrinfo()` using `LD_PRELOAD`.

`socko` is supported only on my computer. That is all.
That's not to say it won't work on your computer. It's just not supported there.

## Building

Run `make`.

## Usage

Run a new program and route it through the proxy: `./socko PROXY_HOST:PROXY_PORT COMMAND [ARGS...]`
e.g. `./socko 127.0.0.1:5555 curl google.com`

Or have it hijack all new processes in your shell:
1. Open a shell, `bash` or `zsh`
1. Run: `export SOCKO_PROXY=PROXY_HOST:PROXY_PORT`
1. Run: `export LD_PRELOAD="$PWD/sockolib.so:$LD_PRELOAD"`
1. Run further commands as normal, e.g. `curl google.com`

This will not work with statically linked programs (think golang programs);
they need to be wrapped in a `bash -c 'COMMAND [ARGS...]` or use `./socko ...`

## How does it work

In hijacking the `connect` syscall, `socko` works similarly to `graftcp` using `ptrace`.
The difference is that instead of re-routing `connect` through a "sidecar" process that handles the SOCKS 5 details,
`socko` points `connect` directly at the proxy and injects extra `sendto`, `recvfrom`
syscalls to perform the SOCKS 5 "handshake".

In hijacking `getaddrinfo()`, `socko` works similarly to `proxychains` using `LD_PRELOAD`.
However, because the `getaddrinfo()` hijacking occurs "in-process" whereas the `connect` hijacking occurs
in the parent `ptrace`-ing process, they need to communicate the hostname.
`getaddrinfo()` in the child process maintains a list of hostnames;
it will then stuff a pointer to the correct one into an IPv6 address and return it back.
Once the `ptracer` gets a hold of the IPv6 address in the `connect` syscall,
it will use that pointer to retrieve the hostname from the memory of the child process (using the power of `ptrace`).

## Limitations

* did I say it's supported only on my computer?
* it's a massive hack
* works only on x86-64
* works only with proxies on IPv4
* does not support any SOCKS 5 authentication (apart from no authentication)
* almost definitely not threadsafe
* hostname hijacking works only if the process calls `getaddrinfo()`.
    Many statically linked programs do not, so they still will not work nice.
    * see also <https://pkg.go.dev/net#hdr-Name_Resolution>

## See also

* <https://github.com/rofl0r/proxychains-ng>
* <http://proxychains.sourceforge.net/>
* <http://tsocks.sourceforge.net/>
* <https://github.com/hmgle/graftcp>
* <https://github.com/NOBLES5E/cproxy>
