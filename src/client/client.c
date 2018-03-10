#include "defs.h"
#include "common.h"
#include "s5.h"
#include "obfs.h"
#include "ssrbuffer.h"
#include "dump_info.h"
#include "ssr_executive.h"
#include "encrypt.h"
#include "tunnel.h"

/* A connection is modeled as an abstraction on top of two simple state
 * machines, one for reading and one for writing.  Either state machine
 * is, when active, in one of three states: busy, done or stop; the fourth
 * and final state, dead, is an end state and only relevant when shutting
 * down the connection.  A short overview:
 *
 *                          busy                  done           stop
 *  ----------|---------------------------|--------------------|------|
 *  readable  | waiting for incoming data | have incoming data | idle |
 *  writable  | busy writing out data     | completed write    | idle |
 *
 * We could remove the done state from the writable state machine. For our
 * purposes, it's functionally equivalent to the stop state.
 *
 * When the connection with upstream has been established, the struct tunnel_ctx
 * moves into a state where incoming data from the client is sent upstream
 * and vice versa, incoming data from upstream is sent to the client.  In
 * other words, we're just piping data back and forth.  See do_proxy()
 * for details.
 *
 * An interesting deviation from libuv's I/O model is that reads are discrete
 * rather than continuous events.  In layman's terms, when a read operation
 * completes, the connection stops reading until further notice.
 *
 * The rationale for this approach is that we have to wait until the data
 * has been sent out again before we can reuse the read buffer.
 *
 * It also pleasingly unifies with the request model that libuv uses for
 * writes and everything else; libuv may switch to a request model for
 * reads in the future.
 */

struct client_ctx {
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    s5_ctx parser;  /* The SOCKS protocol parser. */
};

static struct buffer_t * initial_package_create(const s5_ctx *parser);
static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handshake(struct tunnel_ctx *tunnel);
static void do_handshake_auth(struct tunnel_ctx *tunnel);
static void do_req_start(struct tunnel_ctx *tunnel);
static void do_req_parse(struct tunnel_ctx *tunnel);
static void do_req_lookup(struct tunnel_ctx *tunnel);
static void do_req_connect_start(struct tunnel_ctx *tunnel);
static void do_req_connect(struct tunnel_ctx *tunnel);
static void do_ssr_auth_sent(struct tunnel_ctx *tunnel);
static void do_proxy_start(struct tunnel_ctx *tunnel);
static void do_proxy(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_dying(struct tunnel_ctx *tunnel);
static void tunnel_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size);

void init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct server_env_t *env = (struct server_env_t *)p;

    struct client_ctx *ctx = (struct client_ctx *) calloc(1, sizeof(struct client_ctx));
    ctx->env = env;
    tunnel->data = ctx;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_connected_done = &tunnel_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_alloc_size = &tunnel_alloc_size;

    objects_container_add(ctx->env->tunnel_set, tunnel);

    s5_init(&ctx->parser);
    ctx->cipher = NULL;
}

void client_initialize(uv_tcp_t *lx, unsigned int idle_timeout) {
    uv_loop_t *loop = lx->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    tunnel_initialize(lx, idle_timeout, &init_done_cb, env);
}

static void _do_shutdown_tunnel(void *obj, void *p) {
    tunnel_shutdown((struct tunnel_ctx *)obj);
    (void)p;
}

void client_shutdown(struct server_env_t *env) {
    objects_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

static struct buffer_t * initial_package_create(const s5_ctx *parser) {
    struct buffer_t *buffer = buffer_alloc(SSR_BUFF_SIZE);

    char *iter = buffer->buffer;
    char len;
    iter[0] = (char)parser->atyp;
    iter++;

    switch (parser->atyp) {
    case s5_atyp_ipv4:  // IPv4
        memcpy(iter, parser->daddr, sizeof(struct in_addr));
        iter += sizeof(struct in_addr);
        break;
    case s5_atyp_ipv6:  // IPv6
        memcpy(iter, parser->daddr, sizeof(struct in6_addr));
        iter += sizeof(struct in6_addr);
        break;
    case s5_atyp_host:
        len = (char)strlen((char *)parser->daddr);
        iter[0] = len;
        iter++;
        memcpy(iter, parser->daddr, len);
        iter += len;
        break;
    default:
        ASSERT(0);
        break;
    }
    *((unsigned short *)iter) = htons(parser->dport);
    iter += sizeof(unsigned short);

    buffer->len = iter - buffer->buffer;

    return buffer;
}

/* This is the core state machine that drives the client <-> upstream proxy.
* We move through the initial handshake and authentication steps first and
* end up (if all goes well) in the proxy state where we're just proxying
* data between the client and upstream.
*/
static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    switch (tunnel->state) {
    case session_handshake:
        do_handshake(tunnel);
        break;
    case session_handshake_auth:
        do_handshake_auth(tunnel);
        break;
    case session_req_start:
        do_req_start(tunnel);
        break;
    case session_req_parse:
        do_req_parse(tunnel);
        break;
    case session_req_udp_accoc:
        tunnel_shutdown(tunnel);
        break;
    case session_req_lookup:
        do_req_lookup(tunnel);
        break;
    case session_req_connect:
        do_req_connect(tunnel);
        break;
    case session_ssr_auth_sent:
        do_ssr_auth_sent(tunnel);
        break;
    case session_proxy_start:
        do_proxy_start(tunnel);
        break;
    case session_proxy:
        do_proxy(tunnel, socket);
        break;
    case session_kill:
        tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static void do_handshake(struct tunnel_ctx *tunnel) {
    enum s5_auth_method methods;
    struct socket_ctx *incoming;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_err err;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    parser = &ctx->parser;
    incoming = &tunnel->incoming;
    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        socket_read(incoming);
        tunnel->state = session_handshake;  /* Need more data. */
        return;
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
        * method is s5_auth_none (provided unauthenticated traffic is allowed.)
        * Requires client support however.
        */
        pr_err("junk in handshake");
        tunnel_shutdown(tunnel);
        return;
    }

    if (err != s5_auth_select) {
        pr_err("handshake error: %s", s5_strerror(err));
        tunnel_shutdown(tunnel);
        return;
    }

    methods = s5_auth_methods(parser);
    if ((methods & s5_auth_none) && can_auth_none(tunnel->listener, tunnel)) {
        s5_select_auth(parser, s5_auth_none);
        socket_write(incoming, "\5\0", 2);  /* No auth required. */
        tunnel->state = session_req_start;
        return;
    }

    if ((methods & s5_auth_passwd) && can_auth_passwd(tunnel->listener, tunnel)) {
        /* TODO(bnoordhuis) Implement username/password auth. */
        tunnel_shutdown(tunnel);
        return;
    }

    socket_write(incoming, "\5\377", 2);  /* No acceptable auth. */
    tunnel->state = session_kill;
}

/* TODO(bnoordhuis) Implement username/password auth. */
static void do_handshake_auth(struct tunnel_ctx *tunnel) {
    UNREACHABLE();
    tunnel_shutdown(tunnel);
}

static void do_req_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;

    incoming = &tunnel->incoming;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_done);
    incoming->wrstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    socket_read(incoming);
    tunnel->state = session_req_parse;
}

static void do_req_parse(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_err err;
    struct server_env_t *env;
    struct server_config *config;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    env = ctx->env;
    config = env->config;

    parser = &ctx->parser;
    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        socket_read(incoming);
        tunnel->state = session_req_parse;  /* Need more data. */
        return;
    }

    if (size != 0) {
        pr_err("junk in request %u", (unsigned)size);
        tunnel_shutdown(tunnel);
        return;
    }

    if (err != s5_exec_cmd) {
        pr_err("request error: %s", s5_strerror(err));
        tunnel_shutdown(tunnel);
        return;
    }

    if (parser->cmd == s5_cmd_tcp_bind) {
        /* Not supported but relatively straightforward to implement. */
        pr_warn("BIND requests are not supported.");
        tunnel_shutdown(tunnel);
        return;
    }

    if (parser->cmd == s5_cmd_udp_assoc) {
        // UDP ASSOCIATE requests
        size_t len = sizeof(incoming->buf);
        uint8_t *buf = build_udp_assoc_package(config->udp, config->listen_host, config->listen_port,
            (uint8_t *)incoming->buf, &len);
        socket_write(incoming, buf, len);
        tunnel->state = session_req_udp_accoc;
        return;
    }

    ASSERT(parser->cmd == s5_cmd_tcp_connect);

    ctx->init_pkg = initial_package_create(parser);
    ctx->cipher = tunnel_cipher_create(ctx->env, ctx->init_pkg);

    union sockaddr_universal remote_addr = { 0 };
    if (convert_address(config->remote_host, config->remote_port, &remote_addr) != 0) {
        socket_getaddrinfo(outgoing, config->remote_host);
        tunnel->state = session_req_lookup;
        return;
    }

    memcpy(&outgoing->t.addr, &remote_addr, sizeof(remote_addr));

    do_req_connect_start(tunnel);
}

static void do_req_lookup(struct tunnel_ctx *tunnel) {
    s5_ctx *parser;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    parser = &ctx->parser;
    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (outgoing->result < 0) {
        /* TODO(bnoordhuis) Escape control characters in parser->daddr. */
        pr_err("lookup error for \"%s\": %s",
            parser->daddr,
            uv_strerror((int)outgoing->result));
        /* Send back a 'Host unreachable' reply. */
        socket_write(incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->t.addr.addr.sa_family) {
    case AF_INET:
        outgoing->t.addr.addr4.sin_port = htons(parser->dport);
        break;
    case AF_INET6:
        outgoing->t.addr.addr6.sin6_port = htons(parser->dport);
        break;
    default:
        UNREACHABLE();
    }

    do_req_connect_start(tunnel);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static void do_req_connect_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (!can_access(tunnel->listener, tunnel, &outgoing->t.addr.addr)) {
        pr_warn("connection not allowed by ruleset");
        /* Send a 'Connection not allowed by ruleset' reply. */
        socket_write(incoming, "\5\2\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    err = socket_connect(outgoing);
    if (err != 0) {
        pr_err("connect error: %s", uv_strerror(err));
        tunnel_shutdown(tunnel);
        return;
    }

    tunnel->state = session_req_connect;
}

static void do_req_connect(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (outgoing->result == 0) {
        struct buffer_t *tmp = buffer_clone(ctx->init_pkg);
        if (ssr_ok != tunnel_encrypt(ctx->cipher, tmp)) {
            buffer_free(tmp);
            tunnel_shutdown(tunnel);
            return;
        }
        socket_write(outgoing, tmp->buffer, tmp->len);
        buffer_free(tmp);

        tunnel->state = session_ssr_auth_sent;
        return;
    } else {
        s5_ctx *parser = &ctx->parser;
        char *addr = NULL;
        char ip_str[INET6_ADDRSTRLEN] = { 0 };

        if (parser->atyp == s5_atyp_host) {
            addr = (char *)parser->daddr;
        } else if (parser->atyp == s5_atyp_ipv4) {
            uv_inet_ntop(AF_INET, parser->daddr, ip_str, sizeof(ip_str));
            addr = ip_str;
        } else {
            uv_inet_ntop(AF_INET6, parser->daddr, ip_str, sizeof(ip_str));
            addr = ip_str;
        }
        const char *fmt = "upstream connection \"%s\" error: %s";
        pr_err(fmt, addr, uv_strerror((int)outgoing->result));
        /* Send a 'Connection refused' reply. */
        socket_write(incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    UNREACHABLE();
    tunnel_shutdown(tunnel);
}

static void do_ssr_auth_sent(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_done);
    outgoing->wrstate = socket_stop;

    if (outgoing->result < 0) {
        pr_err("write error: %s", uv_strerror((int)outgoing->result));
        tunnel_shutdown(tunnel);
        return;
    }

    uint8_t *buf;
    struct buffer_t *init_pkg;
    buf = (uint8_t *)incoming->buf;
    init_pkg = ctx->init_pkg;

    buf[0] = 5;  // Version.
    buf[1] = 0;  // Success.
    buf[2] = 0;  // Reserved.
    memcpy(buf + 3, init_pkg->buffer, init_pkg->len);
    socket_write(incoming, buf, 3 + init_pkg->len);
    tunnel->state = session_proxy_start;
}

static void do_proxy_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_done);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);
    incoming->wrstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    socket_read(incoming);
    socket_read(outgoing);
    tunnel->state = session_proxy;
}

/* Proxy incoming data back and forth. */
static void do_proxy(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(socket == incoming || socket == outgoing);

    if (socket == outgoing) {
        struct tunnel_cipher_ctx *tc;
        struct buffer_t *buf = NULL;
        do {
            tc = ctx->cipher;

            buf = buffer_alloc(SSR_BUFF_SIZE);
            buffer_store(buf, outgoing->buf, (size_t)outgoing->result);

            struct buffer_t *feedback = NULL;
            if (ssr_ok != tunnel_decrypt(tc, buf, &feedback)) {
                tunnel_shutdown(tunnel);
                break;
            }
            if (feedback) {
                // SSR logic
                ASSERT(buf->len == 0);
                socket_write(outgoing, feedback->buffer, feedback->len);
                buffer_free(feedback);

                socket_read_stop(incoming);
                socket_read(incoming);
            }
            if (buf->len > 0) {
                socket_write(incoming, buf->buffer, buf->len);
            }
        } while (0);
        buffer_free(buf);
    }

    if (socket == incoming) {
        struct tunnel_cipher_ctx *tc;
        struct buffer_t *buf = NULL;
        do {
            tc = ctx->cipher;

            buf = buffer_alloc(SSR_BUFF_SIZE);
            buffer_store(buf, incoming->buf, (size_t)incoming->result);
            if (ssr_ok != tunnel_encrypt(tc, buf)) {
                tunnel_shutdown(tunnel);
                break;
            }
            if (buf->len > 0) {
                socket_write(outgoing, buf->buffer, buf->len);
            } else if (buf->len == 0) {
                // SSR logic
                socket_read_stop(incoming);
            }
        } while (0);
        buffer_free(buf);
    }
}

static void tunnel_dying(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    objects_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_free(ctx->init_pkg);
    free(ctx);
}

static void tunnel_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    if (tunnel->state != session_proxy) {
        do_next(tunnel, socket);
    }
}

static size_t tunnel_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size) {
    (void)tunnel;
    (void)suggested_size;
    return SSR_BUFF_SIZE;
}
