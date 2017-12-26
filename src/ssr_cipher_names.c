//
//  ssr_cipher_names.c
//  ssrlive
//
//  Created by ssrlive on 12/18/17.
//  Copyright © 2017 ssrlive. All rights reserved.
//

#include <ctype.h>
#include <assert.h>
#include "ssr_cipher_names.h"

#ifndef SIZEOF_ARRAY
#define SIZEOF_ARRAY(a) (sizeof(a)/sizeof((a)[0]))
#endif

static const char *supported_ciphers[SS_CIPHER_NUM] = {
    "none",
    "table",
    "rc4",
    "rc4-md5-6",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf"
};

const char *
ss_cipher_name_from_index(enum ss_cipher_index index)
{
    if (index < SS_NONE || index >= SS_CIPHER_NUM) {
        //LOGE("ss_cipher_name_from_index(): Illegal method");
        return NULL;
    }
    return supported_ciphers[index];
}

static int strcicmp(char const *a, char const *b) {
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a) {
            return d;
        }
    }
}

enum ss_cipher_index
ss_cipher_index_from_name(const char *name)
{
    enum ss_cipher_index m = SS_NONE;
    if (name != NULL) {
        for (m = SS_NONE; m < SS_CIPHER_NUM; ++m) {
            if (strcicmp(name, supported_ciphers[m]) == 0) {
                break;
            }
        }
        if (m >= SS_CIPHER_NUM) {
            //LOGE("Invalid cipher name: %s, use rc4-md5 instead", name);
            // m = SS_RC4_MD5;
        }
    }
    return m;
}


//=========================== ssr_protocol =====================================

const char * ssr_protocol_name_from_index(enum ssr_protocol index) {
#define SSR_PROTOCOL_GEN(_, name, msg) case (name): return (msg);
    switch (index) {
        SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN)
        default:;  // Silence ssr_protocol_max -Wswitch warning.
    }
#undef SSR_PROTOCOL_GEN
    return NULL; // "Invalid index";
}

enum ssr_protocol ssr_protocol_index_from_name(const char *name) {
    struct {
        enum ssr_protocol index;
        char *name;
    } protocol_name_arr[] = {
#define SSR_PROTOCOL_GEN_ARR(_, name, msg) { (name), (msg) },
        SSR_PROTOCOL_MAP(SSR_PROTOCOL_GEN_ARR)
#undef SSR_PROTOCOL_GEN_ARR
    };
    
    enum ssr_protocol result = ssr_protocol_max;
    
    for (size_t index=0; index<SIZEOF_ARRAY(protocol_name_arr); ++index) {
        if (strcicmp(name, protocol_name_arr[index].name) == 0) {
            result = protocol_name_arr[index].index;
            break;
        }
    }
    return result;
}


//=========================== ssr_obfs =========================================

const char * ssr_obfs_name_from_index(enum ssr_obfs index) {
#define SSR_OBFS_GEN(_, name, msg) case (name): return (msg);
    switch (index) {
            SSR_OBFS_MAP(SSR_OBFS_GEN)
        default:;  // Silence ssr_obfs_max -Wswitch warning.
    }
#undef SSR_OBFS_GEN
    return NULL; // "Invalid index";
}

enum ssr_obfs ssr_obfs_index_from_name(const char *name) {
    struct {
        enum ssr_obfs index;
        char *name;
    } obfs_name_arr[] = {
#define SSR_OBFS_GEN_ARR(_, name, msg) { (name), (msg) },
        SSR_OBFS_MAP(SSR_OBFS_GEN_ARR)
#undef SSR_OBFS_GEN_ARR
    };
    
    enum ssr_obfs result = ssr_obfs_max;
    
    for (size_t index=0; index<SIZEOF_ARRAY(obfs_name_arr); ++index) {
        if (strcicmp(name, obfs_name_arr[index].name) == 0) {
            result = obfs_name_arr[index].index;
            break;
        }
    }
    return result;
}
