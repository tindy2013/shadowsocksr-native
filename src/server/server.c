#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <libcork/core.h>
#include "udns.h"

#include "common.h"
#include "dump_info.h"
#include "netutils.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"
#include "config_json.h"
#include "sockaddr_universal.h"
#include "udprelay.h"
#include "tunnel.h"

struct ssr_server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    bool shutting_down;

    uv_tcp_t *tcp_listener;
    struct udp_listener_ctx_t *udp_listener;
};

enum session_state {
    STAGE_ERROR = -1, /* Error detected                   */
    STAGE_INIT = 0,  /* Initial stage                    */
    STAGE_HANDSHAKE = 1,  /* Handshake with client            */
    STAGE_PARSE = 2,  /* Parse the header                 */
    STAGE_RESOLVE = 4,  /* Resolve the hostname             */
    STAGE_STREAM = 5,  /* Stream between client and server */
    session_proxy = STAGE_STREAM, // Connected. Pipe data back and forth.
    session_kill,             // Tear down session.
    session_dead,             // Dead. Safe to free now.
};

struct server_ctx {
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    enum session_state state;
};

static int ssr_server_run_loop(struct server_config *config);
void ssr_server_run_loop_shutdown(struct ssr_server_state *state);

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout);
void server_shutdown(struct server_env_t *env);

void signal_quit_cb(uv_signal_t *handle, int signum);
void tunnel_establish_init_cb(uv_stream_t *server, int status);

static void tunnel_dying(struct tunnel_ctx *tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size);
static bool tunnel_is_on_the_fly(struct tunnel_ctx *tunnel);

static bool is_incoming_ip_legal(struct tunnel_ctx *tunnel);
static bool is_header_complete(const struct buffer_t *buf);
static bool do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket);

void print_server_info(const struct server_config *config);
static const char * parse_opts(int argc, char * const argv[]);
static void usage(void);

int main(int argc, char * const argv[]) {
    struct server_config *config = NULL;
    int err = -1;
    const char *config_path = NULL;

    do {
        set_app_name(argv[0]);

        config_path = DEFAULT_CONF_PATH;
        if (argc > 1) {
            config_path = parse_opts(argc, argv);
        }

        if (config_path == NULL) {
            break;
        }

        config = config_create();
        if (parse_config_file(config_path, config) == false) {
            break;
        }

        config_change_for_server(config);

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password == NULL) {
            break;
        }

        print_server_info(config);

        ssr_server_run_loop(config);

        err = 0;
    } while (0);

    config_release(config);

    if (err != 0) {
        usage();
    }

    return 0;
}

static int ssr_server_run_loop(struct server_config *config) {
    uv_loop_t *loop = NULL;
    struct ssr_server_state *state = NULL;
    int r = 0;

    loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    state = (struct ssr_server_state *) calloc(1, sizeof(*state));
    state->env = ssr_cipher_env_create(config, state);
    loop->data = state->env;

    {
        uv_tcp_t *listener = calloc(1, sizeof(uv_tcp_t));
        uv_tcp_init(loop, listener);

        union sockaddr_universal addr = { 0 };
        addr.addr4.sin_family = AF_INET;
        addr.addr4.sin_port = htons(config->listen_port);
        addr.addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        uv_tcp_bind(listener, &addr.addr, 0);

        int error = uv_listen((uv_stream_t *)listener, 128, tunnel_establish_init_cb);

        if (error != 0) {
            return fprintf(stderr, "Error on listening: %s.\n", uv_strerror(error));
        }
        state->tcp_listener = listener;
    }

    {
        // Setup signal handler
        state->sigint_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, state->sigint_watcher);
        uv_signal_start(state->sigint_watcher, signal_quit_cb, SIGINT);

        state->sigterm_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, state->sigterm_watcher);
        uv_signal_start(state->sigterm_watcher, signal_quit_cb, SIGTERM);
    }

    r = uv_run(loop, UV_RUN_DEFAULT);

    {
        ssr_cipher_env_release(state->env);

        free(state->sigint_watcher);
        free(state->sigterm_watcher);

        free(state);
    }

    free(loop);

    return r;
}

static void listener_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
}

void ssr_server_run_loop_shutdown(struct ssr_server_state *state) {
    if (state == NULL) {
        return;
    }

    if (state->shutting_down) {
        return;
    }
    state->shutting_down = true;

    uv_signal_stop(state->sigint_watcher);
    uv_signal_stop(state->sigterm_watcher);

    if (state->tcp_listener) {
        uv_close((uv_handle_t *)state->tcp_listener, listener_close_done_cb);
    }

#if UDP_RELAY_ENABLE
    if (state->udp_listener) {
        // udprelay_shutdown(state->udp_listener);
    }
#endif // UDP_RELAY_ENABLE

    server_shutdown(state->env);

    pr_info("\n");
    pr_info("terminated.\n");
}

bool _init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct server_env_t *env = (struct server_env_t *)p;

    struct server_ctx *ctx = (struct server_ctx *) calloc(1, sizeof(*ctx));
    ctx->env = env;
    ctx->init_pkg = buffer_alloc(SSR_BUFF_SIZE);
    tunnel->data = ctx;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_alloc_size = &tunnel_alloc_size;
    tunnel->tunnel_is_on_the_fly = &tunnel_is_on_the_fly;

    objects_container_add(ctx->env->tunnel_set, tunnel);

    ctx->cipher = NULL;
    ctx->state = STAGE_INIT;

    return is_incoming_ip_legal(tunnel);
}

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout) {
    uv_loop_t *loop = listener->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    tunnel_initialize(listener, idle_timeout, &_init_done_cb, env);
}

static void _do_shutdown_tunnel(void *obj, void *p) {
    tunnel_shutdown((struct tunnel_ctx *)obj);
    (void)p;
}

void server_shutdown(struct server_env_t *env) {
    objects_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

void signal_quit_cb(uv_signal_t *handle, int signum) {
    ASSERT(handle);
    struct server_env_t *env = (struct server_env_t *)handle->loop->data;
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifndef __MINGW32__
    case SIGUSR1:
#endif
    {
    struct ssr_server_state *state = (struct ssr_server_state *)env->data;
        ASSERT(state);
        ssr_server_run_loop_shutdown(state);
    }
    break;
    default:
        ASSERT(0);
        break;
    }
}

void tunnel_establish_init_cb(uv_stream_t *server, int status) {
    uv_loop_t *loop = server->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    VERIFY(status == 0);
    server_tunnel_initialize((uv_tcp_t *)server, env->config->idle_timeout);
}

static void tunnel_dying(struct tunnel_ctx *tunnel) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    // resolv_cancel(server->query);

    objects_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_free(ctx->init_pkg);
    free(ctx);
}

static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    bool done = false;
    struct server_ctx *ctx = (struct server_ctx *)tunnel->data;
    switch (ctx->state) {
    case STAGE_INIT:
        done = do_init_package(tunnel, socket);
        if (done == false) {
            do_next(tunnel, socket);
        }
        break;
    case STAGE_HANDSHAKE:
        do_handshake(tunnel, socket);
        break;
    case STAGE_PARSE:
        do_parse(tunnel, socket);
        break;
    default:
        break;
    }
}

static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    if (incoming == socket) {
        if (ctx->state < STAGE_PARSE) {
            // report_addr(server->fd, SUSPICIOUS); // collect MALICIOUS IPs.
        }
    }
}

static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    UNREACHABLE();
    tunnel_shutdown(tunnel);
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    if (tunnel->tunnel_is_on_the_fly(tunnel) == false) {
        do_next(tunnel, socket);
    }
}

static size_t tunnel_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size) {
    (void)tunnel;
    (void)suggested_size;
    return SSR_BUFF_SIZE;
}

static bool tunnel_is_on_the_fly(struct tunnel_ctx *tunnel) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    return (ctx->state == session_proxy);
}

static bool is_incoming_ip_legal(struct tunnel_ctx *tunnel) {
    uv_tcp_t *tcp = &tunnel->incoming->handle.tcp;
    // TODO: check incoming ip.
    return true;
}

static bool is_legal_header(const struct buffer_t *buf) {
    bool result = false;
    enum SOCKS5_ADDRTYPE addr_type;
    do {
        if (buf == NULL) {
            break;
        }
        addr_type = (enum SOCKS5_ADDRTYPE) buf->buffer[0];
        switch (addr_type) {
        case SOCKS5_ADDRTYPE_IPV4:
        case SOCKS5_ADDRTYPE_DOMAINNAME:
        case SOCKS5_ADDRTYPE_IPV6:
            result = true;
            break;
        default:
            break;
        }
    } while (0);
    return result;
}

static bool is_header_complete(const struct buffer_t *buf) {
    struct socks5_address addr;
    return socks5_address_parse(buf->buffer, buf->len, &addr);
}

static bool do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    bool done = true;
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    do {
        ASSERT(socket == incoming);
        if (is_completed_package(ctx->env, incoming->buf, (size_t)incoming->result) == false) {
            buffer_store(ctx->init_pkg, incoming->buf, (size_t)incoming->result);
            socket_read(incoming);
            ctx->state = STAGE_INIT;  /* Need more data. */
            break;
        }
        buffer_concatenate(ctx->init_pkg, incoming->buf, (size_t)incoming->result);

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, ctx->init_pkg); // FIXME: error init_pkg

        struct buffer_t *feedback = NULL;
        if (ssr_ok != tunnel_decrypt(ctx->cipher, ctx->init_pkg, &feedback)) {
            // TODO: report_addr(server->fd, MALICIOUS);
            tunnel_shutdown(tunnel);
            break;
        }

        if (is_legal_header(ctx->init_pkg) == false) {
            // report_addr(server->fd, MALFORMED);
            tunnel_shutdown(tunnel);
            break;
        }

        bool ret = is_header_complete(ctx->init_pkg);
        ctx->state = ret ? STAGE_PARSE : STAGE_HANDSHAKE;
        done = false;
    } while (0);
    return done;
}

static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
}

static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    /*
     * Shadowsocks TCP Relay Header:
     *
     *    +------+----------+----------+
     *    | ATYP | DST.ADDR | DST.PORT |
     *    +------+----------+----------+
     *    |  1   | Variable |    2     |
     *    +------+----------+----------+
     */

    /*
     * TCP Relay's payload
     *
     *    +-------------+------+
     *    |    DATA     |      ...
     *    +-------------+------+
     *    |  Variable   |      ...
     *    +-------------+------+
     */

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;

    size_t offset     = 0;
    int need_query = 0;
    char host[257] = { 0 };
    uint16_t port  = 0;
    struct addrinfo info = { 0 };
    struct sockaddr_storage storage = { 0 };

    ASSERT(incoming == socket);

    struct socks5_address s5addr = { 0 };
    if (socks5_address_parse(ctx->init_pkg->buffer, ctx->init_pkg->len, &s5addr) == false) {
        // report_addr(server->fd, MALFORMED);
        tunnel_shutdown(tunnel);
        return;
    }

    //char atyp      = server->buf->array[offset++];
    // get remote addr and port
    if (s5addr.addr_type == SOCKS5_ADDRTYPE_IPV4) {
        // IP V4
        struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
        addr->sin_family = AF_INET;
        addr->sin_addr = s5addr.addr.ipv4;
        dns_ntop(AF_INET, (const void *)&s5addr.addr.ipv4, host, INET_ADDRSTRLEN);
        addr->sin_port   = htons(s5addr.port);
        info.ai_family   = AF_INET;
        info.ai_socktype = SOCK_STREAM;
        info.ai_protocol = IPPROTO_TCP;
        info.ai_addrlen  = sizeof(struct sockaddr_in);
        info.ai_addr     = (struct sockaddr *)addr;
    } else if (s5addr.addr_type == SOCKS5_ADDRTYPE_DOMAINNAME) {
        // Domain name
        uint8_t name_len = (uint8_t) strlen(s5addr.addr.domainname);
        strcpy(host, s5addr.addr.domainname);
        struct cork_ip ip;
        if (cork_ip_init(&ip, host) != -1) {
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            if (ip.version == 4) {
                struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
                dns_pton(AF_INET, host, &(addr->sin_addr));
                addr->sin_port   = htons(s5addr.port);
                addr->sin_family = AF_INET;
                info.ai_family   = AF_INET;
                info.ai_addrlen  = sizeof(struct sockaddr_in);
                info.ai_addr     = (struct sockaddr *)addr;
            } else if (ip.version == 6) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
                dns_pton(AF_INET6, host, &(addr->sin6_addr));
                addr->sin6_port   = htons(s5addr.port);
                addr->sin6_family = AF_INET6;
                info.ai_family    = AF_INET6;
                info.ai_addrlen   = sizeof(struct sockaddr_in6);
                info.ai_addr      = (struct sockaddr *)addr;
            }
        } else {
            if (!validate_hostname(host, name_len)) {
                // report_addr(server->fd, MALFORMED);
                tunnel_shutdown(tunnel);
                return;
            }
            need_query = 1;
        }
    } else if (s5addr.addr_type == SOCKS5_ADDRTYPE_IPV6) {
        // IP V6
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
        size_t in6_addr_len       = sizeof(struct in6_addr);
        addr->sin6_family = AF_INET6;
        addr->sin6_addr = s5addr.addr.ipv6;
        dns_ntop(AF_INET6, (const void *)&s5addr.addr.ipv6, host, INET6_ADDRSTRLEN);
        addr->sin6_port  = htons(s5addr.port);
        info.ai_family   = AF_INET6;
        info.ai_socktype = SOCK_STREAM;
        info.ai_protocol = IPPROTO_TCP;
        info.ai_addrlen  = sizeof(struct sockaddr_in6);
        info.ai_addr     = (struct sockaddr *)addr;
    }

    port = s5addr.port;

    offset = socks5_address_size(&s5addr);

    ctx->init_pkg->len -= offset;
    memmove(ctx->init_pkg->buffer, ctx->init_pkg->buffer + offset, ctx->init_pkg->len);

    /*
    if (!need_query) {
        remote_t *remote = connect_to_remote(EV_A_ &info, server);

        if (remote == NULL) {
            LOGE("connect error");
            close_and_free_server(EV_A_ server);
            return;
        } else {
            server->remote = remote;
            remote->server = server;

            // XXX: should handle buffer carefully
            if (server->buf->len > 0) {
                memcpy(remote->buf->array, server->buf->array, server->buf->len);
                remote->buf->len = server->buf->len;
                remote->buf->idx = 0;
                server->buf->len = 0;
                server->buf->idx = 0;
            }

            // waiting on remote connected event
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    } else {
        query_t *query = ss_malloc(sizeof(query_t));
        memset(query, 0, sizeof(query_t));
        query->server = server;
        snprintf(query->hostname, 256, "%s", host);

        server->stage = STAGE_RESOLVE;
        server->query = resolv_query(host, server_resolve_cb,
                                     query_free_cb, query, port);

        ev_io_stop(EV_A_ & server_recv_ctx->io);
    }
     */
}

void print_server_info(const struct server_config *config) {
    pr_info("ShadowsocksR native server\n");
    pr_info("listen port      %hu", config->listen_port);
    pr_info("method           %s", config->method);
    pr_info("password         %s", config->password);
    pr_info("protocol         %s", config->protocol);
    if (config->protocol_param && strlen(config->protocol_param)) {
        pr_info("protocol_param   %s", config->protocol_param);
    }
    pr_info("obfs             %s", config->obfs);
    if (config->obfs_param && strlen(config->obfs_param)) {
        pr_info("obfs_param       %s", config->obfs_param);
    }
    pr_info("udp relay        %s\n", config->udp ? "yes" : "no");
}

static const char * parse_opts(int argc, char * const argv[]) {
    int opt;

    while (-1 != (opt = getopt(argc, argv, "c:h"))) {
        switch (opt) {
        case 'c':
            return optarg;
            break;
        case 'h':
        default:
            break;
        }
    }
    return NULL;
}

static void usage(void) {
    printf("ShadowsocksR native server\n"
        "\n"
        "Usage:\n"
        "\n"
        "  %s [-c <config file>] [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -c <config file>       Configure file path.\n"
        "                         Default: " DEFAULT_CONF_PATH "\n"
        "  -h                     Show this help message.\n"
        "",
        get_app_name());
    exit(1);
}
