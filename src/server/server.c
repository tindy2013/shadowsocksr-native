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

static int ssr_server_run_loop(struct server_config *config);
void ssr_server_run_loop_shutdown(struct ssr_server_state *state);

void uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void uv_free_buffer(uv_buf_t *buf);
void signal_quit_cb(uv_signal_t *handle, int signum);
void client_accept_cb(uv_stream_t *server, int status);
void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void client_close_done_cb(uv_handle_t* handle);
void client_write_done_cb(uv_write_t* req, int status);

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
    struct ssr_server_state *svr_state = NULL;
    int r = 0;

    uv_loop_t *loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    svr_state = (struct ssr_server_state *) calloc(1, sizeof(*svr_state));
    svr_state->env = ssr_cipher_env_create(config);

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
        svr_state->tcp_listener = listener;
    }

    {
        // Setup signal handler
        svr_state->sigint_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, svr_state->sigint_watcher);
        uv_signal_start(svr_state->sigint_watcher, signal_quit_cb, SIGINT);

        svr_state->sigterm_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, svr_state->sigterm_watcher);
        uv_signal_start(svr_state->sigterm_watcher, signal_quit_cb, SIGTERM);
    }

    loop->data = svr_state;

    r = uv_run(loop, UV_RUN_DEFAULT);

    {
        ssr_cipher_env_release(svr_state->env);

        free(svr_state->sigint_watcher);
        free(svr_state->sigterm_watcher);

        free(svr_state);
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
}

void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    do {
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
