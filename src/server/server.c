#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void uv_alloc_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void uv_free_buffer(uv_buf_t *buf);
void client_accept_cb(uv_stream_t *server, int status);
void client_read_done_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void client_close_done_cb(uv_handle_t* handle);
void client_write_done_cb(uv_write_t* req, int status);

int main(int argc, const char *argv[]) {
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
                fprintf(stderr, "Error on reading client stream: %s.\n", uv_strerror(nread));
            }
            uv_close((uv_handle_t *)stream, client_close_done_cb);
            break;
        }

        ((uv_buf_t *)buf)->len = nread;

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
