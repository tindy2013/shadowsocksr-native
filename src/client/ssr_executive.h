#if !defined(__SSR_EXECUTIVE__)
#define __SSR_EXECUTIVE__ 1


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct cipher_env_t;
struct obfs_manager;
struct tunnel_ctx;
struct clib_slist;

struct server_config {
    char *listen_host;
    unsigned short listen_port;
    char *remote_host;
    unsigned short remote_port;
    char *password;
    char *method;
    char *protocol;
    char *protocol_param;
    char *obfs;
    char *obfs_param;
    bool udp;
    unsigned int idle_timeout; /* Connection idle timeout in ms. */
    char *remarks;
};

struct server_env_t {
    struct server_config *config; // __weak_ptr
    
    struct clib_set *tunnel_set;

    struct cipher_env_t *cipher;

    struct obfs_manager *protocol_plugin;
    struct obfs_manager *obfs_plugin;

    void *protocol_global;
    void *obfs_global;
};

struct tunnel_cipher_ctx {
    struct server_env_t *env; // __weak_ptr
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct obfs_t *protocol;
    struct obfs_t *obfs;
};

#define SSR_ERR_MAP(V)                                                         \
  V( 0, ssr_ok,                 "All is OK.")                                  \
  V(-1, ssr_error_client_decode,      "client decode error.")                  \
  V(-2, ssr_error_invalid_password,   "invalid password or cipher.")           \
  V(-3, ssr_error_client_post_decrypt,"client post decrypt error.")            \

typedef enum ssr_error {
#define SSR_ERR_GEN(code, name, _) name = code,
    SSR_ERR_MAP(SSR_ERR_GEN)
#undef SSR_ERR_GEN
    ssr_max_errors,
} ssr_error;

const char *ssr_strerror(enum ssr_error err);

struct tunnel_cipher_ctx;
struct buffer_t;

void object_safe_free(void **obj);
void string_safe_assign(char **target, const char *value);

#define SECONDS_PER_MINUTE    1000

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     1080
#define DEFAULT_IDLE_TIMEOUT  (60 * SECONDS_PER_MINUTE)
#define DEFAULT_METHOD        "rc4-md5"

struct server_config * config_create(void);
void config_release(struct server_config *cf);

struct server_env_t * ssr_cipher_env_create(struct server_config *config);
void ssr_cipher_env_release(struct server_env_t *env);
void cached_tunnel_add(struct server_env_t *env, struct tunnel_ctx *tunnel);
void cached_tunnel_remove(struct server_env_t *env, struct tunnel_ctx *tunnel);
void cached_tunnel_traverse(struct server_env_t *env, void(*fn)(struct tunnel_ctx *tunnel, void *p), void *p);
struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, const struct buffer_t *init_pkg);
void tunnel_cipher_release(struct tunnel_cipher_ctx *tc);
enum ssr_error tunnel_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf);
enum ssr_error tunnel_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, struct buffer_t **feedback);

#endif // defined(__SSR_EXECUTIVE__)
