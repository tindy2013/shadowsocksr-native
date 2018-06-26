/* Copyright SSRLIVE. All rights reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// for ntohs
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "common.h"
#include "ssr_executive.h"
#include "encrypt.h"
#include "obfsutil.h"
#include "ssrbuffer.h"
#include "obfs.h"
#include "crc32.h"
#include "cstl_lib.h"

const char * ssr_strerror(enum ssr_error err) {
#define SSR_ERR_GEN(_, name, errmsg) case (name): return errmsg;
    switch (err) {
        SSR_ERR_MAP(SSR_ERR_GEN)
        default:;  /* Silence ssr_max_errors -Wswitch warning. */
    }
#undef SSR_ERR_GEN
    return "Unknown error.";
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs);

void object_safe_free(void **obj) {
    if (obj && *obj) {
        free(*obj);
        *obj = NULL;
    }
}

void string_safe_assign(char **target, const char *value) {
    object_safe_free((void **)target);
    if (target && value) {
        *target = strdup(value);
    }
}

struct server_config * config_create(void) {
    struct server_config *config;

    config = (struct server_config *) calloc(1, sizeof(*config));
    string_safe_assign(&config->listen_host, DEFAULT_BIND_HOST);
    string_safe_assign(&config->method, DEFAULT_METHOD);
    config->listen_port = DEFAULT_BIND_PORT;
    config->idle_timeout = DEFAULT_IDLE_TIMEOUT;

    return config;
}

void config_release(struct server_config *cf) {
    if (cf == NULL) {
        return;
    }
    object_safe_free((void **)&cf->listen_host);
    object_safe_free((void **)&cf->remote_host);
    object_safe_free((void **)&cf->password);
    object_safe_free((void **)&cf->method);
    object_safe_free((void **)&cf->protocol);
    object_safe_free((void **)&cf->protocol_param);
    object_safe_free((void **)&cf->obfs);
    object_safe_free((void **)&cf->obfs_param);
    object_safe_free((void **)&cf->remarks);

    object_safe_free((void **)&cf);
}

void config_change_for_server(struct server_config *config) {
    string_safe_assign(&config->listen_host, config->remote_host);
    object_safe_free((void **)&config->remote_host);

    config->listen_port = config->remote_port;
    config->remote_port = 0;
}

static int c_set_compare_element(void *left, void *right) {
    struct tunnel_ctx *l = *(struct tunnel_ctx **)left;
    struct tunnel_ctx *r = *(struct tunnel_ctx **)right;
    if ( l < r ) {
        return -1;
    } else if ( l > r ) {
        return 1;
    } else {
        return 0;
    }
}

struct server_env_t * ssr_cipher_env_create(struct server_config *config, void *data) {
    struct server_env_t *env;
    srand((unsigned int)time(NULL));

    env = (struct server_env_t *) calloc(1, sizeof(struct server_env_t));
    env->cipher = cipher_env_new_instance(config->password, config->method);
    env->config = config;
    env->data = data;

    // init obfs
    init_obfs(env, config->protocol, config->obfs);

    env->tunnel_set = objects_container_create();
    
    return env;
}

void ssr_cipher_env_release(struct server_env_t *env) {
    if (env == NULL) {
        return;
    }
    object_safe_free(&env->protocol_global);
    object_safe_free(&env->obfs_global);
    cipher_env_release(env->cipher);

    objects_container_destroy(env->tunnel_set);
    
    object_safe_free((void **)&env);
}

bool is_completed_package(struct server_env_t *env, const uint8_t *data, size_t size) {
    (void)data;
    return size > (size_t)(enc_get_iv_len(env->cipher) + 1);
}

struct cstl_set * objects_container_create(void) {
    // https://github.com/davinash/cstl/blob/master/test/t_c_set.c#L93
    return cstl_set_new(c_set_compare_element, NULL);
}

void objects_container_destroy(struct cstl_set *set) {
    cstl_set_delete(set);
}

void objects_container_add(struct cstl_set *set, void *obj) {
    ASSERT(set && obj);
    cstl_set_insert(set, &obj, sizeof(void *));
}

void objects_container_remove(struct cstl_set *set, void *obj) {
    ASSERT(cstl_true == cstl_set_exists(set, &obj));
    cstl_set_remove(set, &obj);
}

void objects_container_traverse(struct cstl_set *set, void(*fn)(void *obj, void *p), void *p) {
    struct cstl_iterator *iterator;
    struct cstl_object *element;
    if (set==NULL || fn==NULL) {
        return;
    }
    iterator = cstl_set_new_iterator(set);
    while( (element = iterator->get_next(iterator)) ) {
        void **obj = (void **) iterator->get_value(element);
        if (obj) {
            fn(*obj, p);
            free(obj);
        }
    }
    cstl_set_delete_iterator(iterator);
}



struct cstl_map * obj_map_create(int(*compare_key)(void*,void*), void (*destroy_key)(void*), void (*destroy_value)(void*)) {
    return cstl_map_new(compare_key, destroy_key, destroy_value);
}

void obj_map_destroy(struct cstl_map *map) {
    cstl_map_delete(map);
}

bool obj_map_add(struct cstl_map *map, void *key, size_t k_size, void *value, size_t v_size) {
    return CSTL_ERROR_SUCCESS == cstl_map_insert(map, key, k_size, value, v_size);
}

bool obj_map_exists(struct cstl_map *map, void *key) {
    return cstl_map_exists(map, key) != cstl_false;
}

bool obj_map_replace(struct cstl_map *map, void *key, void *value, size_t v_size) {
    return CSTL_ERROR_SUCCESS == cstl_map_replace(map, key, value, v_size);
}

void obj_map_remove(struct cstl_map *map, void *key) {
    cstl_map_remove(map, key);
}

const void * obj_map_find(struct cstl_map *map, const void *key) {
    return cstl_map_find(map, key);
}

void obj_map_traverse(struct cstl_map *map, void(*fn)(const void *key, const void *value, void *p), void *p) {
    struct cstl_iterator *iterator;
    struct cstl_object *element;
    if (map==NULL || fn==NULL) {
        return;
    }
    iterator = cstl_map_new_iterator(map);
    while( (element = iterator->get_next(iterator)) ) {
        struct cstl_rb_node *current = (struct cstl_rb_node *)iterator->pCurrentElement;
        const void *key = cstl_object_get_data(current->key);
        const void *value = cstl_object_get_data(current->value);
        fn(key, value, p);
    }
    cstl_map_delete_iterator(iterator);
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs) {
    struct obfs_t *protocol_plugin;
    struct obfs_t *obfs_plugin;
    protocol_plugin = new_obfs_instance(protocol);
    if (protocol_plugin) {
        env->protocol_global = protocol_plugin->init_data();
        free_obfs_instance(protocol_plugin);
    }

    obfs_plugin = new_obfs_instance(obfs);
    if (obfs_plugin) {
        env->obfs_global = obfs_plugin->init_data();
        free_obfs_instance(obfs_plugin);
    }
}

struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, size_t tcp_mss) {
    struct server_info_t server_info = { {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    struct server_config *config = env->config;

    struct tunnel_cipher_ctx *tc = (struct tunnel_cipher_ctx *) calloc(1, sizeof(struct tunnel_cipher_ctx));

    tc->env = env;

    // init server cipher
    if (cipher_env_enc_method(env->cipher) > ss_cipher_table) {
        tc->e_ctx = enc_ctx_new_instance(env->cipher, true);
        tc->d_ctx = enc_ctx_new_instance(env->cipher, false);
    }
    // SSR beg

    if (config->remote_host && strlen(config->remote_host)) {
        strcpy(server_info.host, config->remote_host);
    }
    server_info.port = config->remote_port;
    server_info.iv = enc_ctx_get_iv(tc->e_ctx);
    server_info.iv_len = (uint16_t) enc_get_iv_len(env->cipher);
    server_info.key = enc_get_key(env->cipher);
    server_info.key_len = (uint16_t) enc_get_key_len(env->cipher);
    server_info.tcp_mss = (uint16_t) tcp_mss;
    server_info.buffer_size = SSR_BUFF_SIZE;
    server_info.cipher_env = env->cipher;
    {
        server_info.param = config->obfs_param;
        server_info.g_data = env->obfs_global;

        tc->obfs = new_obfs_instance(config->obfs);
        if (tc->obfs) {
            tc->obfs->set_server_info(tc->obfs, &server_info);
        }
    }
    {
        server_info.param = config->protocol_param;
        server_info.g_data = env->protocol_global;

        tc->protocol = new_obfs_instance(config->protocol);
        if (tc->protocol) {
            tc->protocol->set_server_info(tc->protocol, &server_info);
        }
    }

    {
        struct obfs_t *protocol = tc->protocol;
        struct obfs_t *obfs = tc->obfs;
        size_t total_overhead = 
            (protocol ? protocol->get_overhead(protocol) : 0) +
            (obfs ? obfs->get_overhead(obfs) : 0);

        if (protocol) {
            struct server_info_t *info = protocol->get_server_info(protocol);
            info->overhead = (uint16_t)total_overhead;
            info->buffer_size = (uint32_t)(TCP_BUF_SIZE_MAX - total_overhead);
        }
        if (obfs) {
            struct server_info_t *info = obfs->get_server_info(obfs);
            info->overhead = (uint16_t)total_overhead;
            info->buffer_size = (uint32_t)(TCP_BUF_SIZE_MAX - total_overhead);
        }
    }
    // SSR end

   return tc;
}

void tunnel_cipher_release(struct tunnel_cipher_ctx *tc) {
    struct server_env_t *env;
    if (tc == NULL) {
        return;
    }
    env = tc->env;
    if (tc->e_ctx != NULL) {
        enc_ctx_release_instance(env->cipher, tc->e_ctx);
    }
    if (tc->d_ctx != NULL) {
        enc_ctx_release_instance(env->cipher, tc->d_ctx);
    }

    free_obfs_instance(tc->protocol);
    free_obfs_instance(tc->obfs);

    free(tc);
}

bool tunnel_cipher_client_need_feedback(struct tunnel_cipher_ctx *tc) {
    bool protocol = false;
    bool obfs = false;
    struct server_env_t *env = tc->env;
    ASSERT(env);

    if (tc->protocol) {
        protocol = tc->protocol->need_feedback(tc->protocol);
    }
    if (tc->obfs) {
        obfs = tc->obfs->need_feedback(tc->obfs);
    }
    return (protocol || obfs);
}

// insert shadowsocks header
enum ssr_error tunnel_cipher_client_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf) {
    int err;
    struct obfs_t *obfs_plugin;
    struct server_env_t *env = tc->env;
    // SSR beg
    struct obfs_t *protocol_plugin = tc->protocol;
    ASSERT(buf->capacity >= SSR_BUFF_SIZE);
    if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
        buf->len = (size_t)protocol_plugin->client_pre_encrypt(
            tc->protocol, (char **)&buf->buffer, (int)buf->len, &buf->capacity);
    }
    err = ss_encrypt(env->cipher, buf, tc->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        return ssr_error_invalid_password;
    }

    obfs_plugin = tc->obfs;
    if (obfs_plugin && obfs_plugin->client_encode) {
        buf->len = obfs_plugin->client_encode(
            tc->obfs, (char **)&buf->buffer, buf->len, &buf->capacity);
    }
    // SSR end
    return ssr_ok;
}

enum ssr_error tunnel_cipher_client_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, struct buffer_t **feedback)
{
    struct obfs_t *protocol_plugin;
    struct server_env_t *env = tc->env;

    // SSR beg
    struct obfs_t *obfs_plugin = tc->obfs;

    ASSERT(buf->len <= SSR_BUFF_SIZE);

    if (obfs_plugin && obfs_plugin->client_decode) {
        int needsendback = 0;
        ssize_t len = obfs_plugin->client_decode(tc->obfs, (char **)&buf->buffer, buf->len, &buf->capacity, &needsendback);
        if (len < 0) {
            return ssr_error_client_decode;
        }
        buf->len = (size_t)len;
        if (needsendback && obfs_plugin->client_encode) {
            struct buffer_t *sendback = buffer_alloc(SSR_BUFF_SIZE);
            sendback->len = obfs_plugin->client_encode(tc->obfs, (char **)&sendback->buffer, 0, &sendback->capacity);
            ASSERT(feedback);
            *feedback = sendback;
        }
    }
    if (buf->len > 0) {
        int err = ss_decrypt(env->cipher, buf, tc->d_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            return ssr_error_invalid_password;
        }
    }
    protocol_plugin = tc->protocol;
    if (protocol_plugin && protocol_plugin->client_post_decrypt) {
        ssize_t len = protocol_plugin->client_post_decrypt(
            tc->protocol, (char **)&buf->buffer, (int)buf->len, &buf->capacity);
        if (len < 0) {
            return ssr_error_client_post_decrypt;
        }
        buf->len = (size_t)len;
    }
    // SSR end
    return ssr_ok;
}

struct buffer_t * tunnel_cipher_server_encrypt(struct tunnel_cipher_ctx *tc, const struct buffer_t *buf) {
    int err;
    struct server_env_t *env = tc->env;
    struct obfs_t *obfs = tc->obfs;
    struct obfs_t *protocol = tc->protocol;
    struct buffer_t *ret = NULL;
    if (protocol && protocol->server_pre_encrypt) {
        ret = protocol->server_pre_encrypt(protocol, buf);
    } else {
        ret = buffer_clone(buf);
    }
    err = ss_encrypt(env->cipher, ret, tc->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        ASSERT(false);
        buffer_free(ret); ret = NULL;
        return ret;
    }
    if (obfs && obfs->server_encode) {
        struct buffer_t *tmp = obfs->server_encode(obfs, ret);
        buffer_free(ret); ret = tmp;
    }
    return ret;
}

struct buffer_t * 
tunnel_cipher_server_decrypt(struct tunnel_cipher_ctx *tc, 
                             const struct buffer_t *buf, 
                             struct buffer_t **receipt, 
                             struct buffer_t **confirm)
{
    bool need_decrypt = true;
    int err;
    struct server_env_t *env = tc->env;
    struct obfs_t *obfs = tc->obfs;
    struct obfs_t *protocol = tc->protocol;
    struct buffer_t *ret = NULL;
    BUFFER_CONSTANT_INSTANCE(empty, "", 0);

    if (receipt) { *receipt = NULL; }
    if (confirm) { *confirm = NULL; }

    if (obfs && obfs->server_decode) {
        bool need_feedback = false;
        ret = obfs->server_decode(obfs, buf, &need_decrypt, &need_feedback);
        if (ret == NULL) {
            return NULL;
        }
        if (need_feedback) {
            if (receipt) {
                *receipt = obfs->server_encode(obfs, empty);
            }
            buffer_reset(ret);
            return ret;
        }
    } else {
        ret = buffer_clone(buf);
    }
    if (need_decrypt) {
        /*
        // TODO: check IV
        if (is_completed_package(env, ret->buffer, ret->len) == false) {
            buffer_free(ret);
            return NULL;
        }
        */
        if (protocol && protocol->server.recv_iv[0] == 0) {
            size_t iv_len = (size_t) protocol->server.iv_len;
            memmove(protocol->server.recv_iv, ret->buffer, iv_len);
            protocol->server.recv_iv_len = iv_len;
        }

        err = ss_decrypt(env->cipher, ret, tc->d_ctx, max(SSR_BUFF_SIZE, ret->capacity));
        if (err != 0) {
            return NULL;
        }
    }
    if (protocol && protocol->server_post_decrypt) {
        bool feedback = false;
        struct buffer_t *tmp = protocol->server_post_decrypt(protocol, ret, &feedback);
        buffer_free(ret); ret = tmp;
        if (feedback) {
            if (confirm) {
                *confirm  = tunnel_cipher_server_encrypt(tc, empty);
            }
        }
    }
    return ret;
}

bool pre_parse_header(struct buffer_t *data) {
    uint8_t datatype = 0;
    size_t rand_data_size = 0;
    size_t hdr_len = 0;

    if (data==NULL || data->buffer==NULL || data->len==0) {
        return false;
    }

    datatype = data->buffer[0];

    if (datatype == 0x80) {
        if (data->len <= 2) {
            return false;
        }
        rand_data_size = (size_t) data->buffer[1];
        hdr_len = rand_data_size + 2;
        if (hdr_len >= data->len) {
            // header too short, maybe wrong password or encryption method
            return false;
        }

        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;

        return true;
    }
    if (datatype == 0x81) {
        hdr_len = 1;
        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;
        return true;
    }
    if (datatype == 0x82) {
        if (data->len <= 3) {
            return false;
        }
        rand_data_size = (size_t) ntohs( *((uint16_t *)(data->buffer+1)) );
        hdr_len = rand_data_size + 3;
        if (hdr_len >= data->len) {
            // header too short, maybe wrong password or encryption method
            return false;
        }
        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;
        return true;
    }
    if ((datatype == 0x88) || (~datatype == 0x88)) {
        uint32_t crc = 0;
        size_t data_size = 0;
        size_t start_pos = 0;
        size_t origin_len = data->len;
        if (data->len <= (7 + 7)) {
            return false;
        }
        data_size = (size_t) ntohs( *((uint16_t *)(data->buffer+1)) );
        crc = crc32_imp(data->buffer, data_size);
        if (crc != 0xffffffff) {
            // uncorrect CRC32, maybe wrong password or encryption method
            return false;
        }
        start_pos = (size_t)(3 + data->buffer[3]);

        data->len = data_size - (4 + start_pos);
        memmove(data->buffer, data->buffer + start_pos, data->len);

        if (data_size < origin_len) {
            size_t len2 = origin_len - data_size;
            memmove(data->buffer + data->len, data->buffer + data_size, len2);
            data->len += len2;
        }
        return true;
    }

    return true;
}

