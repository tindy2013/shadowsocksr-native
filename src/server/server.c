#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "common.h"
#include "dump_info.h"
#include "netutils.h"
#include "obfsutil.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"
#include "config_json.h"
#include "sockaddr_universal.h"
#include "udprelay.h"
#include "tunnel.h"
#include "daemon_wrapper.h"
#include "cmd_line_parser.h"

#ifndef SSR_MAX_CONN
#define SSR_MAX_CONN 1024
#endif

struct ssr_server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    bool shutting_down;

    uv_tcp_t *tcp_listener;
    struct udp_listener_ctx_t *udp_listener;
    struct cstl_map *resolved_ips;
};

enum tunnel_stage {
    tunnel_stage_initial = 0,  /* Initial stage                    */
    tunnel_stage_receipt_done,
    tunnel_stage_client_feedback,
    tunnel_stage_confirm_done,
    tunnel_stage_resolve_host = 4,  /* Resolve the hostname             */
    tunnel_stage_connect_host,
    tunnel_stage_launch_streaming,
    tunnel_stage_streaming,  /* Stream between client and server */
};

struct server_ctx {
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    enum tunnel_stage stage;
    size_t _tcp_mss;
    size_t _overhead;
    size_t _recv_buffer_size;
    size_t _recv_d_max_size;
};

struct address_timestamp {
    union sockaddr_universal address;
    time_t timestamp;
};

static int ssr_server_run_loop(struct server_config *config);
void ssr_server_shutdown(struct ssr_server_state *state);

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
static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static bool tunnel_is_in_streaming(struct tunnel_ctx *tunnel);
static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size);

static bool is_incoming_ip_legal(struct tunnel_ctx *tunnel);
static bool is_header_complete(const struct buffer_t *buf);
static size_t _get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static void do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_prepare_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_client_feedback(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_resolve_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_connect_host_start(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_connect_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);

static int resolved_ips_compare_key(const void *left, const void *right);
static void resolved_ips_destroy_object(void *obj);

void print_server_info(const struct server_config *config);
static void usage(void);

int main(int argc, char * const argv[]) {
    struct server_config *config = NULL;
    int err = -1;
    struct cmd_line_info *cmds = NULL;

#if __MEM_CHECK__
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
    _CrtSetBreakAlloc(63);
    _CrtSetBreakAlloc(64);
#endif // __MEM_CHECK__

    do {
        set_app_name(argv[0]);

        cmds = cmd_line_info_create(argc, argv);

        if (cmds == NULL) {
            break;
        }

        if (cmds->help_flag) {
            break;
        }

        if (cmds->cfg_file == NULL) {
            string_safe_assign(&cmds->cfg_file, DEFAULT_CONF_PATH);
        }

        config = config_create();
        if (parse_config_file(cmds->cfg_file, config) == false) {
            break;
        }

        config_change_for_server(config);

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password == NULL) {
            break;
        }

        if (cmds->daemon_flag) {
            char param[257] = { 0 };
            sprintf(param, "-c \"%s\"", cmds->cfg_file);
            daemon_wrapper(argv[0], param);
        }

        print_server_info(config);

        ssr_server_run_loop(config);

        err = 0;
    } while (0);

    cmd_line_info_destroy(cmds);

    config_release(config);

    if (err != 0) {
        usage();
    }
#if __MEM_CHECK__
    _CrtDumpMemoryLeaks();
#endif // __MEM_CHECK__
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
        union sockaddr_universal addr = { 0 };
        int error;
        uv_tcp_t *listener = (uv_tcp_t *) calloc(1, sizeof(uv_tcp_t));

        uv_tcp_init(loop, listener);

        addr.addr4.sin_family = AF_INET;
        addr.addr4.sin_port = htons(config->listen_port);
        addr.addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        uv_tcp_bind(listener, &addr.addr, 0);

        error = uv_listen((uv_stream_t *)listener, SSR_MAX_CONN, tunnel_establish_init_cb);

        if (error != 0) {
            return fprintf(stderr, "Error on listening: %s.\n", uv_strerror(error));
        }
        state->tcp_listener = listener;

        state->resolved_ips = obj_map_create(resolved_ips_compare_key,
                                             resolved_ips_destroy_object,
                                             resolved_ips_destroy_object);
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

        obj_map_destroy(state->resolved_ips);

        free(state);
    }

    free(loop);

    return r;
}

static void listener_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
}

void ssr_server_shutdown(struct ssr_server_state *state) {
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
    ctx->_recv_buffer_size = TCP_BUF_SIZE_MAX;
    tunnel->data = ctx;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_is_in_streaming = &tunnel_is_in_streaming;
    tunnel->tunnel_extract_data = &tunnel_extract_data;

    cstl_set_container_add(ctx->env->tunnel_set, tunnel);

    ctx->cipher = NULL;
    ctx->stage = tunnel_stage_initial;

    return is_incoming_ip_legal(tunnel);
}

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout) {
    uv_loop_t *loop = listener->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    tunnel_initialize(listener, idle_timeout, &_init_done_cb, env);
}

static void _do_shutdown_tunnel(const void *obj, void *p) {
    tunnel_shutdown((struct tunnel_ctx *)obj);
    (void)p;
}

void server_shutdown(struct server_env_t *env) {
    cstl_set_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

void signal_quit_cb(uv_signal_t *handle, int signum) {
    struct server_env_t *env;
    ASSERT(handle);
    env = (struct server_env_t *)handle->loop->data;
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifndef __MINGW32__
    case SIGUSR1:
#endif
    {
    struct ssr_server_state *state = (struct ssr_server_state *)env->data;
        ASSERT(state);
        ssr_server_shutdown(state);
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

    cstl_set_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_free(ctx->init_pkg);
    free(ctx);
}

static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    bool done = false;
    struct server_ctx *ctx = (struct server_ctx *)tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    switch (ctx->stage) {
    case tunnel_stage_initial:
        ASSERT(incoming->rdstate == socket_done);
        ASSERT(incoming->wrstate == socket_stop);
        incoming->rdstate = socket_stop;
        do_init_package(tunnel, socket);
        break;
    case tunnel_stage_receipt_done:
        ASSERT(incoming->rdstate == socket_stop);
        ASSERT(incoming->wrstate == socket_done);
        incoming->wrstate = socket_stop;
        socket_read(socket);
        ctx->stage = tunnel_stage_client_feedback;
        break;
    case tunnel_stage_client_feedback:
        ASSERT(incoming->rdstate == socket_done);
        ASSERT(incoming->wrstate == socket_stop);
        incoming->rdstate = socket_stop;
        do_client_feedback(tunnel, socket);
        break;
    case tunnel_stage_confirm_done:
        ASSERT(incoming->rdstate == socket_stop);
        ASSERT(incoming->wrstate == socket_done);
        incoming->wrstate = socket_stop;
        do_prepare_parse(tunnel, socket);
        break;
    case tunnel_stage_resolve_host:
        do_resolve_host_done(tunnel, socket);
        break;
    case tunnel_stage_connect_host:
        do_connect_host_done(tunnel, socket);
        break;
    case tunnel_stage_launch_streaming:
        do_launch_streaming(tunnel, socket);
        break;
    case tunnel_stage_streaming:
        tunnel_traditional_streaming(tunnel, socket);
        break;
    default:
        UNREACHABLE();
        break;
    }
}

static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    if (incoming == socket) {
        if (ctx->stage < tunnel_stage_resolve_host) {
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
    do_next(tunnel, socket);
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    if (socket == tunnel->incoming) {
        return TCP_BUF_SIZE_MAX;
    } else if (socket == tunnel->outgoing) {
        return _get_read_size(tunnel, socket, ctx->_recv_buffer_size);
    } else {
        ASSERT(false);
    }
    return suggested_size;
}

static bool tunnel_is_in_streaming(struct tunnel_ctx *tunnel) {
    // struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    // return (ctx->stage == tunnel_stage_streaming);
    return false;
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

static size_t _get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    // https://github.com/ShadowsocksR-Live/shadowsocksr/blob/manyuser/shadowsocks/tcprelay.py#L812
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    size_t buffer_size;
    size_t frame_size;
    int fd = 0;
    if (ctx->_overhead) {
        return suggested_size;
    }
    fd = uv_stream_fd(&socket->handle.tcp);
    {
    char *tmp = (char *)calloc(suggested_size + 1, sizeof(*tmp));
    buffer_size = (size_t) recv(fd, tmp, (int)suggested_size, MSG_PEEK);
    if (buffer_size == 0) { buffer_size = suggested_size; }
    free(tmp);
    }
    frame_size = ctx->_tcp_mss - ctx->_overhead;

    buffer_size = min(buffer_size, ctx->_recv_d_max_size);
    ctx->_recv_d_max_size = min(ctx->_recv_d_max_size + frame_size, TCP_BUF_SIZE_MAX);

    if (buffer_size == suggested_size) {
        return buffer_size;
    }
    if (buffer_size > frame_size) {
        buffer_size = (buffer_size / frame_size) * frame_size;
    }
    return buffer_size;
}

static void do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct buffer_t *receipt = NULL;
    struct buffer_t *confirm = NULL;
    struct buffer_t *result = NULL;
    do {
        BUFFER_CONSTANT_INSTANCE(buf, incoming->buf->base, incoming->result);
        size_t tcp_mss = _update_tcp_mss(incoming);

        ASSERT(socket == incoming);

        if (incoming->result < 0) {
            tunnel_shutdown(tunnel);
            break;
        }

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, tcp_mss);
        ctx->_tcp_mss = tcp_mss;

        result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &receipt, &confirm);

        if (receipt) {
            ASSERT(confirm == NULL);
            socket_write(incoming, receipt->buffer, receipt->len);
            ctx->stage = tunnel_stage_receipt_done;
            break;
        }

        ASSERT(result /* && result->len!=0 */);
        buffer_replace(ctx->init_pkg, result);

        if (confirm) {
            ASSERT(receipt == NULL);
            socket_write(incoming, confirm->buffer, confirm->len);
            ctx->stage = tunnel_stage_confirm_done;
            break;
        }

        do_prepare_parse(tunnel, socket);
        break;
    } while (0);

    buffer_free(receipt);
    buffer_free(confirm);
    buffer_free(result);
}

static void do_prepare_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct buffer_t *init_pkg = ctx->init_pkg;
    do {
        struct server_info_t *info;
        struct obfs_t *protocol = NULL;
        struct obfs_t *obfs = NULL;

        protocol = ctx->cipher->protocol;
        obfs = ctx->cipher->obfs;

        pre_parse_header(init_pkg);

        info = protocol ? protocol->get_server_info(protocol) : (obfs ? obfs->get_server_info(obfs) : NULL);
        if (info) {
            info->head_len = (int) get_s5_head_size(init_pkg->buffer, init_pkg->len, 30);
            ctx->_overhead = info->overhead;
            ctx->_recv_buffer_size = info->buffer_size;
        }
        ctx->_recv_d_max_size = TCP_BUF_SIZE_MAX;

        if (is_legal_header(init_pkg) == false) {
            // report_addr(server->fd, MALFORMED);
            tunnel_shutdown(tunnel);
            break;
        }

        if (is_header_complete(init_pkg) == false) {
            tunnel_shutdown(tunnel);
            break;
        }

        do_parse(tunnel, socket);
    } while (0);
}

static void do_client_feedback(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    BUFFER_CONSTANT_INSTANCE(buf, incoming->buf->base, incoming->result);
    struct buffer_t *result = NULL;
    struct buffer_t *receipt = NULL;
    struct buffer_t *confirm = NULL;
    do {
        ASSERT(incoming == socket);

        if (incoming->result < 0) {
            pr_err("write error: %s", uv_strerror((int)incoming->result));
            tunnel_shutdown(tunnel);
            break;
        }

        result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &receipt, &confirm);
        ASSERT(receipt == NULL);
        if (result==NULL || result->len==0) {
            tunnel_shutdown(tunnel);
            break;
        }

        buffer_concatenate2(ctx->init_pkg, result);

        if (confirm) {
            socket_write(incoming, confirm->buffer, confirm->len);
            ctx->stage = tunnel_stage_confirm_done;
            break;
        }

        do_prepare_parse(tunnel, socket);
        break;
    } while(0);
    buffer_free(result);
    buffer_free(receipt);
    buffer_free(confirm);
}

static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    UNREACHABLE();
}

static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    /*
     * Shadowsocks TCP Relay Header, same as SOCKS5:
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
    struct socket_ctx *outgoing = tunnel->outgoing;
    size_t offset     = 0;
    const char *host = NULL;
    struct socks5_address *s5addr;
    union sockaddr_universal target;
    bool ipFound = true;

    ASSERT(incoming == socket);

    // get remote addr and port
    s5addr = tunnel->desired_addr;
    memset(s5addr, 0, sizeof(*s5addr));
    if (socks5_address_parse(ctx->init_pkg->buffer, ctx->init_pkg->len, s5addr) == false) {
        // report_addr(server->fd, MALFORMED);
        tunnel_shutdown(tunnel);
        return;
    }

    offset = socks5_address_size(s5addr);
    buffer_shorten(ctx->init_pkg, offset, ctx->init_pkg->len - offset);

    host = s5addr->addr.domainname;

    if (socks5_address_to_universal(s5addr, &target) == false) {
        ASSERT(s5addr->addr_type == SOCKS5_ADDRTYPE_DOMAINNAME);

        if (uv_ip4_addr(host, s5addr->port, &target.addr4) != 0) {
            if (uv_ip6_addr(host, s5addr->port, &target.addr6) != 0) {
                ipFound = false;
            }
        }
    }

    if (ipFound == false) {
        struct ssr_server_state *state = (struct ssr_server_state *)ctx->env->data;
        struct address_timestamp **addr = NULL;
        addr = (struct address_timestamp **)obj_map_find(state->resolved_ips, &host);
        if (addr && *addr) {
            target = (*addr)->address;
            target.addr4.sin_port = htons(s5addr->port);
            ipFound = true;
        }
    }

    if (ipFound == false) {
        if (!validate_hostname(host, strlen(host))) {
            // report_addr(server->fd, MALFORMED);
            tunnel_shutdown(tunnel);
            return;
        }
        ctx->stage = tunnel_stage_resolve_host;
        outgoing->addr.addr4.sin_port = htons(s5addr->port);
        socket_getaddrinfo(outgoing, host);
    } else {
        outgoing->addr = target;
        do_connect_host_start(tunnel, socket);
    }
}

static void do_resolve_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(outgoing == socket);
    ASSERT(incoming->rdstate == socket_stop || incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop || incoming->wrstate == socket_done);
    ASSERT(outgoing->rdstate == socket_stop || outgoing->rdstate == socket_done);
    ASSERT(outgoing->wrstate == socket_stop || outgoing->wrstate == socket_done);

    if (outgoing->result < 0) {
        tunnel_shutdown(tunnel);
        return;
    }

    {
        char *host = tunnel->desired_addr->addr.domainname;
        struct ssr_server_state *state = (struct ssr_server_state *)ctx->env->data;
        if (obj_map_exists(state->resolved_ips, &host) == false) {
            struct address_timestamp *addr = NULL;
            addr = (struct address_timestamp *)calloc(1, sizeof(struct address_timestamp));
            addr->address = outgoing->addr;
            addr->timestamp = time(NULL);
            host = strdup(host);
            obj_map_add(state->resolved_ips, &host, sizeof(void *), &addr, sizeof(void *));
        }
    }

    do_connect_host_start(tunnel, socket);
}

static void do_connect_host_start(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    ctx->stage = tunnel_stage_connect_host;
    err = socket_connect(outgoing);

    if (err != 0) {
        pr_err("connect error: %s", uv_strerror(err));
        tunnel_shutdown(tunnel);
        return;
    }
}

static void do_connect_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(outgoing == socket);
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (outgoing->result == 0) {
        if (ctx->init_pkg->len > 0) {
            socket_write(outgoing, ctx->init_pkg->buffer, ctx->init_pkg->len);
            ctx->stage = tunnel_stage_launch_streaming;
        } else {
            outgoing->wrstate = socket_done;
            do_launch_streaming(tunnel, socket);
        }
        return;
    } else {
        socket_dump_error_info("upstream connection", socket);
        tunnel_shutdown(tunnel);
        return;
    }
}

static void do_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(outgoing == socket);
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

    socket_read(incoming);
    socket_read(outgoing);
    ctx->stage = tunnel_stage_streaming;
}

static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size) {
    struct tunnel_ctx *tunnel = socket->tunnel;
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t *buf = NULL;
    uint8_t *result = NULL;

    if (socket==NULL || allocator==NULL || size==NULL) {
        return result;
    }
    *size = 0;

    {
        BUFFER_CONSTANT_INSTANCE(src, socket->buf->base, socket->result);
        if (socket == tunnel->outgoing) {
            buf = tunnel_cipher_server_encrypt(cipher_ctx, src);
        } else if (socket == tunnel->incoming) {
            struct buffer_t *receipt = NULL;
            struct buffer_t *confirm = NULL;
            buf = tunnel_cipher_server_decrypt(cipher_ctx, src, &receipt, &confirm);
            ASSERT(receipt == NULL);
            ASSERT(confirm == NULL);
        } else {
            ASSERT(0);
        }
    }

    if (buf) {
        size_t len = buf->len;
        *size = len;
        result = (uint8_t *)allocator(len + 1);
        memcpy(result, buf->buffer, len);

        buffer_free(buf);
    }

    return result;
}

static int resolved_ips_compare_key(const void *left, const void *right) {
    char *l = *(char **)left;
    char *r = *(char **)right;
    return strcmp(l, r);
}

static void resolved_ips_destroy_object(void *obj) {
    if (obj) {
        void *str = *((void **)obj);
        if (str) {
            free(str);
        }
    }
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

static void usage(void) {
    printf("ShadowsocksR native server\n"
        "\n"
        "Usage:\n"
        "\n"
        "  %s [-d] [-c <config file>] [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -d                     Run in background as a daemon.\n"
        "  -c <config file>       Configure file path.\n"
        "                         Default: " DEFAULT_CONF_PATH "\n"
        "  -h                     Show this help message.\n"
        "",
        get_app_name());
}
