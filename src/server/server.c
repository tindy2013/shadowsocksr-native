#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>

#include "common.h"
#include "dump_info.h"
#include "ssr_executive.h"
#include "config_json.h"
#include "sockaddr_universal.h"
#include "udprelay.h"

struct ssr_server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    bool shutting_down;

    uv_tcp_t *tcp_listener;
    struct udp_listener_ctx_t *udp_listener;
};

enum socket_state {
    socket_stop,  // Stopped.
    socket_busy,  // Busy; waiting for incoming data or for a write to complete.
    socket_done,  // Done; read incoming data or write finished.
    socket_dead,
};

struct socket_ctx {
    enum socket_state rdstate;
    enum socket_state wrstate;
    unsigned int idle_timeout;
    struct tunnel_ctx *tunnel;  // Backlink to owning tunnel context.
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  // For detecting timeouts.
    uv_write_t write_req;
    // We only need one of these at a time so make them share memory.
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        union sockaddr_universal addr;
        uint8_t buf[SSR_BUFF_SIZE];  // Scratch space. Used to read data into.
    } t;
};

enum session_state {
    session_handshake,        // Wait for client handshake.
    session_handshake_auth,   // Wait for client authentication data.
    session_req_start,        // Start waiting for request data.
    session_req_parse,        // Wait for request data.
    session_req_udp_accoc,
    session_req_lookup,       // Wait for upstream hostname DNS lookup to complete.
    session_req_connect,      // Wait for uv_tcp_connect() to complete.
    session_ssr_auth_sent,
    session_proxy_start,      // Connected. Start piping data.
    session_proxy,            // Connected. Pipe data back and forth.
    session_kill,             // Tear down session.
    session_dead,             // Dead. Safe to free now.
};

struct tunnel_ctx {
    enum session_state state;
    struct server_env_t *env;
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    uv_tcp_t *listener;  // Backlink to owning listener context.
    //s5_ctx parser;  // The SOCKS protocol parser.
    struct socket_ctx incoming;  // Connection with the SOCKS client.
    struct socket_ctx outgoing;  // Connection with upstream.
    int ref_count;
};


static int ssr_server_run_loop(struct server_config *config);
void ssr_server_run_loop_shutdown(struct ssr_server_state *state);

void uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void uv_free_buffer(uv_buf_t *buf);
void signal_quit_cb(uv_signal_t *handle, int signum);
void client_accept_cb(uv_stream_t *server, int status);
void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void client_close_done_cb(uv_handle_t* handle);
void client_write_done_cb(uv_write_t* req, int status);

void ssr_tunnel_initialize(uv_tcp_t *listener);
void ssr_tunnel_shutdown(struct tunnel_ctx *tunnel);
static bool tunnel_is_dead(struct tunnel_ctx *tunnel);
static void tunnel_add_ref(struct tunnel_ctx *tunnel);
static void tunnel_release(struct tunnel_ctx *tunnel);
static void socket_read(struct socket_ctx *c);
static void socket_write(struct socket_ctx *c, const void *data, size_t len);
static void socket_write_done_cb(uv_write_t *req, int status);
static void socket_close(struct socket_ctx *c);
static void socket_close_done_cb(uv_handle_t *handle);
static void socket_timer_reset(struct socket_ctx *c);
static void socket_timer_expire_cb(uv_timer_t *handle);

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
    struct ssr_server_state *state = NULL;
    int r = 0;

    uv_loop_t *loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    state = (struct ssr_server_state *) calloc(1, sizeof(*state));
    state->env = ssr_cipher_env_create(config);

    {
        uv_tcp_t *listener = calloc(1, sizeof(uv_tcp_t));
        uv_tcp_init(loop, listener);

        union sockaddr_universal addr;
        uv_ip4_addr(DEFAULT_BIND_HOST, config->listen_port, &addr.addr4);
        uv_tcp_bind(listener, &addr.addr, 0);

        int error = uv_listen((uv_stream_t *)listener, 128, client_accept_cb);

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

    loop->data = state;

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

static void _do_shutdown_tunnel(void *obj, void *p) {
#if 0
    tunnel_shutdown((struct tunnel_ctx *)obj);
    (void)p;
#endif
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

    objects_container_traverse(state->env->tunnel_set, &_do_shutdown_tunnel, NULL);

    pr_info("\n");
    pr_info("terminated.\n");
}

void signal_quit_cb(uv_signal_t *handle, int signum) {
    struct ssr_server_state *state = (struct ssr_server_state *)handle->loop->data;
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifndef __MINGW32__
    case SIGUSR1:
#endif
    {
        assert(state);
        ssr_server_run_loop_shutdown(state);
    }
    break;
    default:
        assert(0);
        break;
    }
}

void client_accept_cb(uv_stream_t *server, int status) {
    ssr_tunnel_initialize((uv_tcp_t *)server);
    /*
    do {
        uv_loop_t *loop = server->loop;
        int r = status;

        // tunnel_initialize((uv_tcp_t *)server, (struct server_env_t *)server->data);

        if (r < 0) {
            fprintf(stderr, "Error on listening: %s.\n", uv_strerror(r));
            break;
        }

        uv_tcp_t *client = (uv_tcp_t *)calloc(1, sizeof(uv_tcp_t));
        uv_tcp_init(loop, client);

        // now let bind the client to the server to be used for incomings
        r = uv_accept(server, (uv_stream_t *)client);
        if (r != 0) {
            // close client stream on error
            client_close_done_cb((uv_handle_t *)client);
            break;
        }
        // start reading from stream
        r = uv_read_start((uv_stream_t *)client, uv_alloc_buffer, client_read_done_cb);
        if (r) {
            fprintf(stderr, "Error on reading client stream: %s.\n", uv_strerror(r));
        }
    } while (0);
        */
}

void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;
    c = CONTAINER_OF(stream, struct socket_ctx, handle);
    do {
        /*
        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            // there is an error or EOF
            assert(nread == UV_EOF || nread == UV_ECONNRESET);
            if (nread != UV_EOF) {
                fprintf(stderr, "Error on reading client stream: %s.\n", uv_strerror((int)nread));
            }
            uv_close((uv_handle_t *)stream, client_close_done_cb);
            break;
        }

        ((uv_buf_t *)buf)->len = (uv_buf_len_t)nread;

        // write sync the incoming buffer to the socket
        uv_write_t * req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
        int r = uv_write(req, stream, buf, 1, &client_write_done_cb);

        if (r) {
            fprintf(stderr, "Error on writing client stream: %s.\n", uv_strerror(r));
        }
        */

        tunnel = c->tunnel;

        uv_read_stop(&c->handle.stream);

        if (tunnel_is_dead(tunnel)) {
            return;
        }

        if (nread <= 0) {
            // http://docs.libuv.org/en/v1.x/stream.html
            ASSERT(nread == UV_EOF || nread == UV_ECONNRESET);
            if (nread < 0) { ssr_tunnel_shutdown(tunnel); }
            return;
        }

        ASSERT(c->t.buf == (uint8_t *)buf->base);
        ASSERT(c->rdstate == socket_busy);
        c->rdstate = socket_done;
        c->result = nread;

        //do_next(tunnel);

    } while (0);

    uv_free_buffer((uv_buf_t *)buf);
}

void uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    (void)handle;
    *buf = uv_buf_init((char *)calloc(1, size), (unsigned int)size);
}

void uv_free_buffer(uv_buf_t *buf) {
    free(buf->base);
    buf->base = NULL;
    buf->len = 0;
}

void client_close_done_cb(uv_handle_t* handle) {
    free(handle);
}

void client_write_done_cb(uv_write_t* req, int status) {
    free(req);
}

void ssr_tunnel_initialize(uv_tcp_t *listener) {
    uv_loop_t *loop = listener->loop;
    struct ssr_server_state *state = loop->data;
    struct server_env_t *env = state->env;
    struct server_config *config = env->config;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct tunnel_ctx *tunnel;

    tunnel = (struct tunnel_ctx *) calloc(1, sizeof(*tunnel));

    tunnel->env = env;
    tunnel->cipher = NULL;
    tunnel->listener = listener;
    tunnel->state = session_handshake;
    tunnel->ref_count = 0;
    //s5_init(&tunnel->parser);

    incoming = &tunnel->incoming;
    incoming->tunnel = tunnel;
    incoming->result = 0;
    incoming->rdstate = socket_stop;
    incoming->wrstate = socket_stop;
    incoming->idle_timeout = config->idle_timeout;
    assert(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    assert(0 == uv_accept((uv_stream_t *)listener, &incoming->handle.stream));
    assert(0 == uv_timer_init(loop, &incoming->timer_handle));

    outgoing = &tunnel->outgoing;
    outgoing->tunnel = tunnel;
    outgoing->result = 0;
    outgoing->rdstate = socket_stop;
    outgoing->wrstate = socket_stop;
    outgoing->idle_timeout = config->idle_timeout;
    assert(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    assert(0 == uv_timer_init(loop, &outgoing->timer_handle));

    socket_read(incoming);

    objects_container_add(tunnel->env->tunnel_set, tunnel);
}

void ssr_tunnel_shutdown(struct tunnel_ctx *tunnel) {
    if (tunnel_is_dead(tunnel) != false) {
        return;
    }

    /* Try to cancel the request. The callback still runs but if the
    * cancellation succeeded, it gets called with status=UV_ECANCELED.
    */
    if (tunnel->state == session_req_lookup) {
        uv_cancel(&tunnel->outgoing.t.req);
    }

    socket_close(&tunnel->incoming);
    socket_close(&tunnel->outgoing);

    tunnel->state = session_dead;
}

static bool tunnel_is_dead(struct tunnel_ctx *tunnel) {
    return (tunnel->state == session_dead);
}

static void tunnel_add_ref(struct tunnel_ctx *tunnel) {
    tunnel->ref_count++;
}

static void tunnel_release(struct tunnel_ctx *tunnel) {
    tunnel->ref_count--;
    if (tunnel->ref_count == 0) {
        objects_container_remove(tunnel->env->tunnel_set, tunnel);
        if (tunnel->cipher) {
            tunnel_cipher_release(tunnel->cipher);
        }
        //buffer_free(tunnel->init_pkg);
        free(tunnel);
    }
}

static void socket_read(struct socket_ctx *c) {
    ASSERT(c->rdstate == socket_stop);
    CHECK(0 == uv_read_start(&c->handle.stream, uv_alloc_buffer, client_read_done_cb));
    c->rdstate = socket_busy;
    socket_timer_reset(c);
}

static void socket_write(struct socket_ctx *c, const void *data, size_t len) {
    uv_buf_t buf;

    ASSERT(c->wrstate == socket_stop || c->wrstate == socket_done);
    c->wrstate = socket_busy;

    /* It's okay to cast away constness here, uv_write() won't modify the
    * memory.
    */
    buf = uv_buf_init((char *)data, (unsigned int)len);

    CHECK(0 == uv_write(&c->write_req, &c->handle.stream, &buf, 1, socket_write_done_cb));
    socket_timer_reset(c);
}

static void socket_write_done_cb(uv_write_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, write_req);
    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (status == UV_ECANCELED) {
        ssr_tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(c->wrstate == socket_busy);
    c->wrstate = socket_done;
    c->result = status;
    //do_next(tunnel);
}

static void socket_close(struct socket_ctx *c) {
    struct tunnel_ctx *tunnel = c->tunnel;
    ASSERT(c->rdstate != socket_dead);
    ASSERT(c->wrstate != socket_dead);
    c->rdstate = socket_dead;
    c->wrstate = socket_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;

    tunnel_add_ref(tunnel);
    uv_close(&c->handle.handle, socket_close_done_cb);
    tunnel_add_ref(tunnel);
    uv_close((uv_handle_t *)&c->timer_handle, socket_close_done_cb);
}

static void socket_close_done_cb(uv_handle_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = (struct socket_ctx *) handle->data;
    tunnel = c->tunnel;

    tunnel_release(tunnel);
}

static void socket_timer_reset(struct socket_ctx *c) {
    CHECK(0 == uv_timer_start(&c->timer_handle,
        socket_timer_expire_cb,
        c->idle_timeout,
        0));
}

static void socket_timer_expire_cb(uv_timer_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, timer_handle);
    c->result = UV_ETIMEDOUT;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    ssr_tunnel_shutdown(tunnel);
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
