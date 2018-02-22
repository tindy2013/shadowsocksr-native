#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "obfs.h"

int rand_bytes(uint8_t *output, int len);

#include "obfsutil.h"
#include "crc32.h"
#include "http_simple.h"
#include "tls1.2_ticket.h"
#include "verify.h"
#include "auth.h"
#include "auth_chain.h"

#include "../encrypt.h"
#include "ssr_cipher_names.h"

void *
init_data(void)
{
    return malloc(1);
}

struct obfs_t *
new_obfs(void)
{
    struct obfs_t * obfs = (struct obfs_t*)malloc(sizeof(struct obfs_t));
    obfs->l_data = NULL;
    return obfs;
}

int
get_overhead(struct obfs_t *obfs)
{
    return 0;
}

void
set_server_info(struct obfs_t *obfs, struct server_info_t *server)
{
    memmove(&obfs->server, server, sizeof(struct server_info_t));
}

void
get_server_info(struct obfs_t *obfs, struct server_info_t *server)
{
    memmove(server, &obfs->server, sizeof(struct server_info_t));
}

void
dispose_obfs(struct obfs_t *obfs)
{
    free(obfs);
}

struct obfs_manager *
new_obfs_manager(const char *plugin_name)
{
    if (plugin_name == NULL || strlen(plugin_name)==0) {
        return NULL;
    }
    if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_origin)) == 0) {
        // origin
        return NULL;
    }
    if (strcmp(plugin_name, ssr_obfs_name_of_type(ssr_obfs_plain)) == 0) {
        // plain
        return NULL;
    }
    init_crc32_table();
    init_shift128plus();
    if (strcmp(plugin_name, ssr_obfs_name_of_type(ssr_obfs_http_simple)) == 0) {
        // http_simple
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = http_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = http_simple_dispose;

        plugin->client_encode = http_simple_client_encode;
        plugin->client_decode = http_simple_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, ssr_obfs_name_of_type(ssr_obfs_http_post)) == 0) {
        // http_post
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = http_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = http_simple_dispose;

        plugin->client_encode = http_post_client_encode;
        plugin->client_decode = http_simple_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, ssr_obfs_name_of_type(ssr_obfs_tls_1_2_ticket_auth)) == 0) {
        // tls1.2_ticket_auth
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = tls12_ticket_auth_init_data;
        plugin->new_obfs = tls12_ticket_auth_new_obfs;
        plugin->get_overhead = tls12_ticket_auth_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = tls12_ticket_auth_dispose;

        plugin->client_encode = tls12_ticket_auth_client_encode;
        plugin->client_decode = tls12_ticket_auth_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, ssr_obfs_name_of_type(ssr_obfs_tls_1_2_ticket_fastauth)) == 0) {
        // tls1.2_ticket_fastauth
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = tls12_ticket_fastauth_init_data;
        plugin->new_obfs = tls12_ticket_fastauth_new_obfs;
        plugin->get_overhead = tls12_ticket_fastauth_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = tls12_ticket_fastauth_dispose;

        plugin->client_encode = tls12_ticket_fastauth_client_encode;
        plugin->client_decode = tls12_ticket_fastauth_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_verify_simple)) == 0) {
        // verify_simple
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = verify_simple_new_obfs;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = verify_simple_dispose;

        plugin->client_pre_encrypt = verify_simple_client_pre_encrypt;
        plugin->client_post_decrypt = verify_simple_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_simple)) == 0) {
        // auth_simple
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_simple_client_pre_encrypt;
        plugin->client_post_decrypt = auth_simple_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_sha1)) == 0) {
        // auth_sha1
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_sha1_v2)) == 0) {
        // auth_sha1_v2
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_v2_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_v2_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_sha1_v4)) == 0) {
        // auth_sha1_v4
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_v4_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_v4_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_aes128_md5)) == 0 || strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_aes128_sha1)) == 0) {
        // auth_aes128_md5
        // auth_aes128_sha1
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_aes128_md5)) == 0) {
            plugin->new_obfs = auth_aes128_md5_new_obfs;
        } else {
            plugin->new_obfs = auth_aes128_sha1_new_obfs;
        }
        plugin->get_overhead = auth_aes128_sha1_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_aes128_sha1_client_pre_encrypt;
        plugin->client_post_decrypt = auth_aes128_sha1_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_aes128_sha1_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_aes128_sha1_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_a)) == 0) {
        // auth_chain_a
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_a_init_data;
        plugin->new_obfs = auth_chain_a_new_obfs;
        plugin->get_overhead = auth_chain_a_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_a_set_server_info;
        plugin->dispose = auth_chain_a_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_b)) == 0) {
        // auth_chain_b
        struct obfs_manager *plugin = (struct obfs_manager *)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_b_init_data;
        plugin->new_obfs = auth_chain_b_new_obfs;
        plugin->get_overhead = auth_chain_b_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_b_set_server_info;
        plugin->dispose = auth_chain_b_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_c)) == 0) {
        // auth_chain_c
        struct obfs_manager *plugin = (struct obfs_manager *) calloc(1, sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_c_init_data;
        plugin->new_obfs = auth_chain_c_new_obfs;
        plugin->get_overhead = auth_chain_c_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_c_set_server_info;
        plugin->dispose = auth_chain_c_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_d)) == 0) {
        // auth_chain_d
        struct obfs_manager *plugin = (struct obfs_manager *) calloc(1, sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_d_init_data;
        plugin->new_obfs = auth_chain_d_new_obfs;
        plugin->get_overhead = auth_chain_d_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_d_set_server_info;
        plugin->dispose = auth_chain_d_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_e)) == 0) {
        // auth_chain_e
        struct obfs_manager *plugin = (struct obfs_manager *)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_e_init_data;
        plugin->new_obfs = auth_chain_e_new_obfs;
        plugin->get_overhead = auth_chain_e_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_e_set_server_info;
        plugin->dispose = auth_chain_e_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, ssr_protocol_name_of_type(ssr_protocol_auth_chain_f)) == 0) {
        // auth_chain_f
        struct obfs_manager *plugin = (struct obfs_manager *)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_f_init_data;
        plugin->new_obfs = auth_chain_f_new_obfs;
        plugin->get_overhead = auth_chain_f_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = auth_chain_f_set_server_info;
        plugin->dispose = auth_chain_f_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    }
    assert(0); // LOGE("Load obfs '%s' failed", plugin_name);
    return NULL;
}

void
free_obfs_manager(struct obfs_manager *plugin)
{
    free(plugin);
}
