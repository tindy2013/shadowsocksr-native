#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>

#include "common.h"
#include "dump_info.h"
#include "ssr_executive.h"
#include "config_json.h"

static int ssr_server_run_loop(struct server_config *config);

void uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void uv_free_buffer(uv_buf_t *buf);
void client_accept_cb(uv_stream_t *server, int status);
void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void client_close_done_cb(uv_handle_t* handle);
void client_write_done_cb(uv_write_t* req, int status);

void print_remote_info(const struct server_config *config);
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

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password == NULL || config->remote_host == NULL) {
            break;
        }

        print_remote_info(config);

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

    uv_loop_t *loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    uv_tcp_t *server = calloc(1, sizeof(uv_tcp_t));
    uv_tcp_init(loop, server);

    struct sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", 3000, &addr);
    uv_tcp_bind(server, (struct sockaddr *)&addr, 0);

    int r = uv_listen((uv_stream_t *)server, 128, client_accept_cb);

    if (r) {
        return fprintf(stderr, "Error on listening: %s.\n", uv_strerror(r));
    }

    r = uv_run(loop, UV_RUN_DEFAULT);

    free(server);

    uv_loop_close(loop);
    free(loop);

    return r;
}

void client_accept_cb(uv_stream_t *server, int status) {
    do {
        uv_loop_t *loop = server->loop;
        int r = status;

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

void print_remote_info(const struct server_config *config) {
    char remote_host[256] = { 0 };
    strcpy(remote_host, config->remote_host);
    if (strlen(remote_host) > 4) {
        for (size_t i = 4; i < strlen(remote_host); i++) {
            remote_host[i] = '*';
        }
    }

    char password[256] = { 0 };
    strcpy(password, config->password);
    if (strlen(password) > 2) {
        for (size_t i = 2; i < strlen(password); i++) {
            password[i] = '*';
        }
    }

    pr_info("remote server    %s:%hu", remote_host, config->remote_port);
    pr_info("method           %s", config->method);
    pr_info("password         %s", password);
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
        "  %s -c <config file> [-h]\n"
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
