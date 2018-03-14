#if !defined(__tunnel_h__)
#define __tunnel_h__ 1

#include <uv.h>
#include <stdbool.h>

struct tunnel_ctx;

enum socket_state {
    socket_stop,  /* Stopped. */
    socket_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    socket_done,  /* Done; read incoming data or write finished. */
    socket_dead,
};

struct socket_ctx {
    enum socket_state rdstate;
    enum socket_state wrstate;
    unsigned int idle_timeout;
    struct tunnel_ctx *tunnel;  /* Backlink to owning tunnel context. */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
                              /* We only need one of these at a time so make them share memory. */
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        union sockaddr_universal addr;
    } t;
    uint8_t *buf; /* Scratch space. Used to read data into. */
    size_t buf_size;
};

struct tunnel_ctx {
    void *data;
    bool terminated;
    bool getaddrinfo_pending;
    uv_tcp_t *listener;  /* Backlink to owning listener context. */
    struct socket_ctx *incoming;  /* Connection with the SOCKS client. */
    struct socket_ctx *outgoing;  /* Connection with upstream. */
    int ref_count;

    void(*tunnel_dying)(struct tunnel_ctx *tunnel);
    void(*tunnel_timeout_expire_done)(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
    void(*tunnel_outgoing_connected_done)(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
    void(*tunnel_read_done)(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
    void(*tunnel_getaddrinfo_done)(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
    void(*tunnel_write_done)(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
    size_t(*tunnel_alloc_size)(struct tunnel_ctx *tunnel, size_t suggested_size);
    bool(*tunnel_is_on_the_fly)(struct tunnel_ctx *tunnel);
};

void tunnel_initialize(uv_tcp_t *lx, unsigned int idle_timeout, bool(*init_done_cb)(struct tunnel_ctx *tunnel, void *p), void *p);
void tunnel_shutdown(struct tunnel_ctx *tunnel);
int socket_connect(struct socket_ctx *c);
void socket_read(struct socket_ctx *c);
void socket_read_stop(struct socket_ctx *c);
void socket_getaddrinfo(struct socket_ctx *c, const char *hostname);
void socket_write(struct socket_ctx *c, const void *data, size_t len);

#endif // !defined(__tunnel_h__)
