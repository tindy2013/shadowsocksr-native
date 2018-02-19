/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
//#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "ssrcipher.h"
#if UDP_RELAY_ENABLE
#include "udprelay.h"
#endif // UDP_RELAY_ENABLE

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 63
#endif

struct udp_server_ctx_t;

struct listener_t {
    uv_tcp_t *tcp_server;
    struct udp_server_ctx_t *udp_server;
};

struct server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    int listener_count;
    struct listener_t *listeners;
};

static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void listen_incoming_connection_cb(uv_stream_t *server, int status);
static void signal_quit(uv_signal_t* handle, int signum);

int shadowsocks_r_loop_run(struct server_config *cf, struct server_state **state) {
    uv_loop_t * loop = NULL;
    struct addrinfo hints;
    struct server_state *svr_state;
    int err;

    loop = calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    svr_state = (struct server_state *) calloc(1, sizeof(*svr_state));
    svr_state->listeners = NULL;
    svr_state->env = ssr_cipher_env_create(cf);
    svr_state->sigint_watcher = (uv_signal_t *) calloc(1, sizeof(uv_signal_t));
    svr_state->sigterm_watcher = (uv_signal_t *) calloc(1, sizeof(uv_signal_t));

    /* Resolve the address of the interface that we should bind to.
    * The getaddrinfo callback starts the server and everything else.
    */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_getaddrinfo_t *req = (uv_getaddrinfo_t *)malloc(sizeof(*req));
    req->data = svr_state;

    err = uv_getaddrinfo(loop, req, getaddrinfo_done_cb, cf->listen_host, NULL, &hints);
    if (err != 0) {
        pr_err("getaddrinfo: %s", uv_strerror(err));
        return err;
    }

    // Setup signal handler
    uv_signal_init(loop, svr_state->sigint_watcher);
    uv_signal_start(svr_state->sigint_watcher, signal_quit, SIGINT);
    svr_state->sigint_watcher->data = svr_state;

    uv_signal_init(loop, svr_state->sigterm_watcher);
    uv_signal_start(svr_state->sigterm_watcher, signal_quit, SIGTERM);
    svr_state->sigterm_watcher->data = svr_state;

    if (state) {
        *state = svr_state;
    }

    /* Start the event loop.  Control continues in getaddrinfo_done_cb(). */
    err = uv_run(loop, UV_RUN_DEFAULT);
    if (err != 0) {
        pr_err("uv_run: %s", uv_strerror(err));
    }

    ssr_cipher_env_release(svr_state->env);

    if (svr_state->listeners) {
        free(svr_state->listeners);
    }

    free(svr_state->sigint_watcher);
    free(svr_state->sigterm_watcher);
    
    free(svr_state);

    uv_loop_close(loop);
    free(loop); loop = NULL;
    
    return err;
}

static void tcp_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
}

void shadowsocks_r_loop_shutdown(struct server_state *state) {
    if (state==NULL) {
        return;
    }

    uv_signal_stop(state->sigint_watcher);
    uv_signal_stop(state->sigterm_watcher);

    if (state->listeners && state->listener_count) {
        for (size_t n = 0; n < state->listener_count; ++n) {
            struct listener_t *listener = state->listeners + n;

            uv_tcp_t *tcp_server = listener->tcp_server;
            if (tcp_server) {
                uv_close((uv_handle_t *)tcp_server, tcp_close_done_cb);
            }

#if UDP_RELAY_ENABLE
            struct udp_server_ctx_t *udp_server = listener->udp_server;
            if (udp_server) {
                udprelay_shutdown(udp_server);
            }
#endif // UDP_RELAY_ENABLE
        }
    }
}

/* Bind a server to each address that getaddrinfo() reported. */
static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int ipv4_naddrs;
    unsigned int ipv6_naddrs;
    struct server_state *state;
    struct server_env_t *env;
    const struct server_config *cf;
    struct addrinfo *ai;
    const void *addrv = NULL;
    const char *what;
    uv_loop_t *loop;
    unsigned int n;
    int err;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;

    loop = req->loop;

    state = (struct server_state *) req->data;
    ASSERT(state);
    env = state->env;
    cf = env->config;

    free(req);

    if (status < 0) {
        pr_err("getaddrinfo(\"%s\"): %s", cf->listen_host, uv_strerror(status));
        uv_freeaddrinfo(addrs);
        return;
    }

    ipv4_naddrs = 0;
    ipv6_naddrs = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            ipv4_naddrs += 1;
        } else if (ai->ai_family == AF_INET6) {
            ipv6_naddrs += 1;
        }
    }

    if (ipv4_naddrs == 0 && ipv6_naddrs == 0) {
        pr_err("%s has no IPv4/6 addresses", cf->listen_host);
        uv_freeaddrinfo(addrs);
        return;
    }

    state->listener_count = (ipv4_naddrs + ipv6_naddrs);
    state->listeners = calloc(state->listener_count, sizeof(state->listeners[0]));

    n = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }

        if (ai->ai_family == AF_INET) {
            s.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
            s.addr4.sin_port = htons(cf->listen_port);
            addrv = &s.addr4.sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            s.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
            s.addr6.sin6_port = htons(cf->listen_port);
            addrv = &s.addr6.sin6_addr;
        } else {
            UNREACHABLE();
        }

        if (uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf)) != 0) {
            UNREACHABLE();
        }

        struct listener_t *listener = state->listeners + n;

        listener->tcp_server = (uv_tcp_t *)calloc(1, sizeof(listener->tcp_server[0]));
        uv_tcp_t *tcp_server = listener->tcp_server;
        CHECK(0 == uv_tcp_init(loop, tcp_server));

        what = "uv_tcp_bind";
        err = uv_tcp_bind(tcp_server, &s.addr, 0);
        if (err == 0) {
            what = "uv_listen";
            tcp_server->data = env;
            err = uv_listen((uv_stream_t *)tcp_server, 128, listen_incoming_connection_cb);
        }

        if (err != 0) {
            pr_err("%s(\"%s:%hu\"): %s", what, addrbuf, cf->listen_port, uv_strerror(err));
            while (n > 0) {
                n -= 1;
                uv_close((uv_handle_t *)tcp_server, NULL);
            }
            break;
        }

        pr_info("listening on %s:%hu", addrbuf, cf->listen_port);

#if UDP_RELAY_ENABLE
        if (cf->udp) {
            int remote_addr_len = (s.addr.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            listener->udp_server = udprelay_begin(loop,
                cf->listen_host, cf->listen_port,
                &s.addr, remote_addr_len,
                NULL, 0, cf->idle_timeout, NULL,
                state->env->cipher,
                cf->protocol, cf->protocol_param);
        }
#endif // UDP_RELAY_ENABLE

        n += 1;
    }

    if (cf->udp) {
        pr_info("udprelay enabled");
    }

    uv_freeaddrinfo(addrs);
}

static void listen_incoming_connection_cb(uv_stream_t *server, int status) {
    CHECK(status == 0);
    tunnel_initialize((uv_tcp_t *)server, (struct server_env_t *)server->data);
}

bool can_auth_none(const uv_tcp_t *lx, const struct tunnel_ctx *cx) {
    return true;
}

bool can_auth_passwd(const uv_tcp_t *lx, const struct tunnel_ctx *cx) {
    return false;
}

bool can_access(const uv_tcp_t *lx, const struct tunnel_ctx *cx, const struct sockaddr *addr) {
    const struct sockaddr_in6 *addr6;
    const struct sockaddr_in *addr4;
    const uint32_t *p;
    uint32_t a, b, c, d;

    /* TODO(bnoordhuis) Implement proper access checks.  For now, just reject
    * traffic to localhost.
    */
    if (addr->sa_family == AF_INET) {
        addr4 = (const struct sockaddr_in *) addr;
        d = ntohl(addr4->sin_addr.s_addr);
        return (d >> 24) != 0x7F;
    }

    if (addr->sa_family == AF_INET6) {
        addr6 = (const struct sockaddr_in6 *) addr;
        p = (const uint32_t *)&addr6->sin6_addr.s6_addr;
        a = ntohl(p[0]);
        b = ntohl(p[1]);
        c = ntohl(p[2]);
        d = ntohl(p[3]);
        if (a == 0 && b == 0 && c == 0 && d == 1) {
            return false;  /* "::1" style address. */
        }
        if (a == 0 && b == 0 && c == 0xFFFF && (d >> 24) == 0x7F) {
            return false;  /* "::ffff:127.x.x.x" style address. */
        }
        return true;
    }

    return false;
}

static void signal_quit(uv_signal_t* handle, int signum) {
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifndef __MINGW32__
    case SIGUSR1:
#endif
    {
        assert(handle);
        struct server_state *state = (struct server_state *)handle->data;
        assert(state);
        shadowsocks_r_loop_shutdown(state);
    }
        break;
    default:
        assert(0);
        break;
    }
}
