//
//  ssr_cipher_names.h
//  ssrlive
//
//  Created by ssrlive on 12/18/17.
//  Copyright © 2017 ssrlive. All rights reserved.
//

#ifndef ssr_cipher_names_h
#define ssr_cipher_names_h

#include <stdio.h>

enum ss_cipher_index {
    SS_NONE,
    SS_TABLE,
    SS_RC4,
    SS_RC4_MD5_6,
    SS_RC4_MD5,
    SS_AES_128_CFB,
    SS_AES_192_CFB,
    SS_AES_256_CFB,
    SS_AES_128_CTR,
    SS_AES_192_CTR,
    SS_AES_256_CTR,
    SS_BF_CFB,
    SS_CAMELLIA_128_CFB,
    SS_CAMELLIA_192_CFB,
    SS_CAMELLIA_256_CFB,
    SS_CAST5_CFB,
    SS_DES_CFB,
    SS_IDEA_CFB,
    SS_RC2_CFB,
    SS_SEED_CFB,
    SS_SALSA20,
    SS_CHACHA20,
    SS_CHACHA20IETF,
    SS_CIPHER_NUM,
};

const char * ss_cipher_name_from_index(enum ss_cipher_index index);
enum ss_cipher_index ss_cipher_index_from_name(const char *name);


#define SSR_PROTOCOL_MAP(V)                                                    \
    V(0, ssr_protocol_origin,           "origin")                              \
    V( 4, ssr_protocol_auth_sha1,       "auth_sha1")                           \
    V( 5, ssr_protocol_auth_sha1_v2,    "auth_sha1_v2")                        \
    V( 6, ssr_protocol_auth_sha1_v4,    "auth_sha1_v4")                        \
    V( 7, ssr_protocol_auth_aes128_md5, "auth_aes128_md5")                     \
    V( 8, ssr_protocol_auth_aes128_sha1,"auth_aes128_sha1")                    \
    V( 9, ssr_protocol_auth_chain_a,    "auth_chain_a")                        \
//    V( 1, ssr_protocol_verify_simple,   "verify_simple")                       \
//    V( 2, ssr_protocol_verify_sha1,     "verify_sha1")                         \
//    V( 3, ssr_protocol_auth_simple,     "auth_simple")                         \
//    V(10, ssr_protocol_auth_chain_b,    "auth_chain_b")                        \

typedef enum ssr_protocol {
#define SSR_PROTOCOL_GEN(code, name, _) name = code,
    SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN)
#undef SSR_PROTOCOL_GEN
    ssr_protocol_max,
} ssr_protocol;

const char * ssr_protocol_name_from_index(enum ssr_protocol index);
enum ssr_protocol ssr_protocol_index_from_name(const char *name);


#define SSR_OBFS_MAP(V)                                                        \
    V(0, ssr_obfs_plain,                    "plain")                           \
    V(1, ssr_obfs_http_simple,              "http_simple")                     \
    V(2, ssr_obfs_http_post,                "http_post")                       \
    V(4, ssr_obfs_tls_1_2_ticket_auth,      "tls1.2_ticket_auth")              \
//    V(3, ssr_obfs_tls_1_0_session_auth,     "tls1.0_session_auth")             \
//    V(5, ssr_obfs_tls_1_2_ticket_fastauth,  "tls1.2_ticket_fastauth")          \

typedef enum ssr_obfs {
#define SSR_OBFS_GEN(code, name, _) name = code,
    SSR_OBFS_MAP(SSR_OBFS_GEN)
#undef SSR_OBFS_GEN
    ssr_obfs_max,
} ssr_obfs;

const char * ssr_obfs_name_from_index(enum ssr_obfs index);
enum ssr_obfs ssr_obfs_index_from_name(const char *name);

#endif /* ssr_cipher_names_h */
