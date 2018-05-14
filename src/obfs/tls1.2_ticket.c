#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "obfs.h"
#include "tls1.2_ticket.h"
#include "obfsutil.h"
#include "encrypt.h"
#include "ssrbuffer.h"

BUFFER_CONSTANT_INSTANCE(tls_version, "\x03\x03", 2);

struct tls12_ticket_auth_global_data {
    uint8_t local_client_id[32];
};

struct tls12_ticket_auth_local_data {
    int handshake_status;
    uint8_t *send_buffer;
    size_t   send_buffer_size;
    struct buffer_t *recv_buffer;
    struct buffer_t *client_id;
    uint32_t max_time_dif;
    int      send_id;
    bool     fastauth;
};

static void tls12_ticket_auth_local_data_init(struct tls12_ticket_auth_local_data* local) {
    local->handshake_status = 0;
    local->send_buffer = malloc(0);
    local->send_buffer_size = 0;
    local->recv_buffer = buffer_alloc(SSR_BUFF_SIZE);
    local->client_id = buffer_alloc(SSR_BUFF_SIZE);
    local->max_time_dif = 60 * 60 *24; // time dif (second) setting
    local->send_id = 0;
    local->fastauth = false;
}

void * tls12_ticket_auth_init_data(void) {
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*) malloc(sizeof(struct tls12_ticket_auth_global_data));
    rand_bytes(global->local_client_id, sizeof(global->local_client_id));
    return global;
}

struct obfs_t * tls12_ticket_auth_new_obfs(void) {
    struct obfs_t * obfs = new_obfs();
    obfs->l_data = calloc(1, sizeof(struct tls12_ticket_auth_local_data));
    tls12_ticket_auth_local_data_init((struct tls12_ticket_auth_local_data*)obfs->l_data);
    return obfs;
}

int tls12_ticket_auth_get_overhead(struct obfs_t *obfs) {
    return 5;
}

void tls12_ticket_auth_dispose(struct obfs_t *obfs) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    if (local->send_buffer != NULL) {
        free(local->send_buffer);
        local->send_buffer = NULL;
    }
    buffer_free(local->recv_buffer);
    free(local);
    dispose_obfs(obfs);
}

static void tls12_sha1_hmac(struct obfs_t *obfs,
                            const struct buffer_t *client_id,
                            const struct buffer_t *msg,
                            uint8_t digest[SHA1_BYTES])
{
    size_t id_size = client_id->len;
    size_t key_size = obfs->server.key_len;
    uint8_t *key = (uint8_t*)malloc(key_size + id_size);
    memcpy(key, obfs->server.key, key_size);
    memcpy(key + key_size, client_id->buffer, id_size);
    ss_sha1_hmac_with_key(digest, msg->buffer, msg->len, key, (key_size + id_size));
    free(key);
}

static int tls12_ticket_pack_auth_data(struct obfs_t *obfs, const uint8_t client_id[32], uint8_t outdata[32]) {
    struct server_info_t *server = &obfs->server;
    uint8_t *key;
    char hash[SHA1_BYTES];
    int out_size = 32;
    time_t t = time(NULL);
    outdata[0] = (uint8_t)(t >> 24);
    outdata[1] = (uint8_t)(t >> 16);
    outdata[2] = (uint8_t)(t >> 8);
    outdata[3] = (uint8_t)t;
    rand_bytes((uint8_t*)outdata + 4, 18);

    {
        BUFFER_CONSTANT_INSTANCE(pClientID, client_id, 32);
        BUFFER_CONSTANT_INSTANCE(pMsg, outdata, 22);
        tls12_sha1_hmac(obfs, pClientID, pMsg, hash);
    }
    memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
    return out_size;
}

void tls12_ticket_auth_pack_data(const uint8_t *encryptdata, uint16_t start, uint16_t len, uint8_t *out_buffer, uint16_t outlength) {
    out_buffer[outlength] = 0x17;
    out_buffer[outlength + 1] = 0x3;
    out_buffer[outlength + 2] = 0x3;
    out_buffer[outlength + 3] = (uint8_t)(len >> 8);
    out_buffer[outlength + 4] = (uint8_t)len;
    memcpy(out_buffer + outlength + 5, encryptdata + start, len);
}

size_t tls12_ticket_auth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity) {
    uint8_t *encryptdata = (uint8_t *)*pencryptdata;
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server.g_data;
    uint8_t * out_buffer = NULL;

    if (local->handshake_status == 8) {
        if (datalength < (SSR_BUFF_SIZE / 2)) {
            if (*capacity < datalength + 5) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)((datalength + 5) * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            memmove(encryptdata + 5, encryptdata, datalength);
            encryptdata[0] = 0x17;
            encryptdata[1] = 0x3;
            encryptdata[2] = 0x3;
            encryptdata[3] = (uint8_t)(datalength >> 8);
            encryptdata[4] = (uint8_t)datalength;
            return datalength + 5;
        } else {
            size_t start = 0;
            size_t outlength = 0;
            size_t len;
            out_buffer = (uint8_t*)malloc((size_t)(datalength + (SSR_BUFF_SIZE * 2)));
            while (datalength - start > SSR_BUFF_SIZE) {
                len = xorshift128plus() % (SSR_BUFF_SIZE * 2) + 100;
                if (len > datalength - start) {
                    len = datalength - start;
                }
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
                start += len;
            }
            if (datalength - start > 0) {
                len = datalength - start;
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
            }
            if (*capacity < outlength) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            memcpy(encryptdata, out_buffer, outlength);
            free(out_buffer);
            return outlength;
        }
    }

    if (datalength > 0) {
        if (datalength < (SSR_BUFF_SIZE / 2)) {
            local->send_buffer = (uint8_t *)realloc(local->send_buffer, (local->send_buffer_size + datalength + 5));
            tls12_ticket_auth_pack_data(encryptdata, 0, (uint16_t)datalength, local->send_buffer, (uint16_t)local->send_buffer_size);
            local->send_buffer_size += datalength + 5;
        } else {
            size_t start = 0;
            size_t outlength = 0;
            size_t len;
            out_buffer = (uint8_t *)malloc(datalength + (SSR_BUFF_SIZE * 2));
            while (datalength - start > SSR_BUFF_SIZE) {
                len = xorshift128plus() % (SSR_BUFF_SIZE * 2) + 100;
                if (len > datalength - start) {
                    len = datalength - start;
                }
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
                start += len;
            }
            if (datalength - start > 0) {
                len = datalength - start;
                tls12_ticket_auth_pack_data(encryptdata, (uint16_t)start, (uint16_t)len, out_buffer, (uint16_t)outlength);
                outlength += len + 5;
            }
            if (*capacity < outlength) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
                encryptdata = (uint8_t *)*pencryptdata;
            }
            local->send_buffer = (uint8_t *)realloc(local->send_buffer, (local->send_buffer_size + outlength));
            memcpy(local->send_buffer + local->send_buffer_size, out_buffer, outlength);
            local->send_buffer_size += outlength;
            free(out_buffer);
        }
    }

    if (local->handshake_status == 0) {
#define CSTR_DECL(name, len, str) const char* (name) = (str); const size_t (len) = (sizeof(str) - 1)
        CSTR_DECL(tls_data0, tls_data0_len, "\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00");
        CSTR_DECL(tls_data1, tls_data1_len, "\xff\x01\x00\x01\x00");
        CSTR_DECL(tls_data2, tls_data2_len, "\x00\x17\x00\x00\x00\x23\x00\xd0");
        CSTR_DECL(tls_data3, tls_data3_len, "\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"
                //"00150066000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // padding
                );
        uint8_t * tls_data = (uint8_t *)calloc(SSR_BUFF_SIZE, sizeof(uint8_t));
        size_t tls_data_len = 0;
        char hosts[(SSR_BUFF_SIZE / 2)];
        char * phost[128];
        int host_num = 0;
        int pos;
        char sni[256] = {0};
        char* param = NULL;
        size_t sni_len;
        size_t ticket_len;
        uint8_t *pdata;
        int len;

        memcpy(tls_data, tls_data1, tls_data1_len);
        tls_data_len += tls_data1_len;

        if (obfs->server.param && strlen(obfs->server.param) > 0) {
            param = obfs->server.param;
        } else {
            param = obfs->server.host;
        }
        strncpy(hosts, param, sizeof hosts);
        phost[host_num++] = hosts;
        for (pos = 0; hosts[pos]; ++pos) {
            if (hosts[pos] == ',') {
                phost[host_num++] = &hosts[pos + 1];
                hosts[pos] = 0;
            }
        }
        host_num = (int)(xorshift128plus() % (uint64_t)host_num);

        snprintf(sni, sizeof sni, "%s", phost[host_num]);
        sni_len = strlen(sni);
        if (sni_len > 0 && sni[sni_len - 1] >= '0' && sni[sni_len - 1] <= '9') {
            sni_len = 0;
        }
        tls_data[tls_data_len] = '\0';
        tls_data[tls_data_len + 1] = '\0';
        tls_data[tls_data_len + 2] = (uint8_t)((sni_len + 5) >> 8);
        tls_data[tls_data_len + 3] = (uint8_t)(sni_len + 5);
        tls_data[tls_data_len + 4] = (uint8_t)((sni_len + 3) >> 8);
        tls_data[tls_data_len + 5] = (uint8_t)(sni_len + 3);
        tls_data[tls_data_len + 6] = '\0';
        tls_data[tls_data_len + 7] = (uint8_t)(sni_len >> 8);
        tls_data[tls_data_len + 8] = (uint8_t)sni_len;
        memcpy(tls_data + tls_data_len + 9, sni, (size_t) sni_len);
        tls_data_len += 9 + sni_len;
        memcpy(tls_data + tls_data_len, tls_data2, tls_data2_len);
        tls_data_len += tls_data2_len;
        ticket_len = (xorshift128plus() % (uint64_t)164) * 2 + 64;
        tls_data[tls_data_len - 1] = (uint8_t)(ticket_len & 0xff);
        tls_data[tls_data_len - 2] = (uint8_t)(ticket_len >> 8);
        rand_bytes(tls_data + tls_data_len, (int)ticket_len);
        tls_data_len += ticket_len;
        memcpy(tls_data + tls_data_len, tls_data3, tls_data3_len);
        tls_data_len += tls_data3_len;

        datalength = 11 + 32 + 1 + 32 + tls_data0_len + 2 + tls_data_len;
        out_buffer = (uint8_t *)malloc((size_t)datalength);
        pdata = out_buffer + datalength - tls_data_len;
        len = (int)tls_data_len;
        memcpy(pdata, tls_data, tls_data_len);
        pdata[-1] = (uint8_t)tls_data_len;
        pdata[-2] = (uint8_t)(tls_data_len >> 8);
        pdata -= 2; len += 2;
        memcpy(pdata - tls_data0_len, tls_data0, tls_data0_len);
        pdata -= tls_data0_len; len += (int)tls_data0_len;
        memcpy(pdata - 32, global->local_client_id, 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x20;
        pdata -= 1; len += 1;
        tls12_ticket_pack_auth_data(obfs, global->local_client_id, pdata - 32);
        pdata -= 32; len += 32;
        pdata[-1] = 0x3;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = (uint8_t)len;
        pdata[-2] = (uint8_t)(len >> 8);
        pdata[-3] = 0;
        pdata[-4] = 1;
        pdata -= 4; len += 4;

        pdata[-1] = (uint8_t)len;
        pdata[-2] = (uint8_t)(len >> 8);
        pdata -= 2; len += 2;
        pdata[-1] = 0x1;
        pdata[-2] = 0x3; // tls version
        pdata -= 2; len += 2;
        pdata[-1] = 0x16; // tls handshake
        pdata -= 1; len += 1;

        local->handshake_status = 1;

        free(tls_data);
    } else if (datalength == 0 || local->fastauth) {
        size_t tmp = datalength;
        uint8_t *pdata;
        uint8_t *key;
        char hash[SHA1_BYTES];

        datalength = local->send_buffer_size + 43;
        out_buffer = (uint8_t *)malloc(datalength);
        pdata = out_buffer;
        memcpy(pdata, "\x14\x03\x03\x00\x01\x01", 6);
        pdata += 6;
        memcpy(pdata, "\x16\x03\x03\x00\x20", 5);
        pdata += 5;
        rand_bytes((uint8_t*)pdata, 22);
        pdata += 22;

        {
            BUFFER_CONSTANT_INSTANCE(pClientID, global->local_client_id, 32);
            BUFFER_CONSTANT_INSTANCE(pMsg, out_buffer, (pdata - out_buffer));
            tls12_sha1_hmac(obfs, pClientID, pMsg, hash);
        }
        memcpy(pdata, hash, OBFS_HMAC_SHA1_LEN);

        pdata += OBFS_HMAC_SHA1_LEN;
        memcpy(pdata, local->send_buffer, local->send_buffer_size);
        free(local->send_buffer);
        local->send_buffer = NULL;
        local->send_buffer_size = 0;

        if (tmp == 0) {
            local->handshake_status = 8;
        }
    } else {
        return 0;
    }
    if (*capacity < datalength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (datalength * 2));
        encryptdata = (uint8_t *)*pencryptdata;
    }
    memmove(encryptdata, out_buffer, datalength);
    free(out_buffer);
    return datalength;
}

ssize_t tls12_ticket_auth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback) {
    char *encryptdata = *pencryptdata;
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server.g_data;

    *needsendback = 0;
    if (local->handshake_status == 8) {
        buffer_concatenate(local->recv_buffer, (const uint8_t *)encryptdata, datalength);
        datalength = 0;
        while (local->recv_buffer->len > 5) {
            size_t size;
            if (local->recv_buffer->buffer[0] != 0x17) {
                return -1;
            }
            size = (size_t)ntohs(*((uint16_t *)(local->recv_buffer->buffer + 3)));
            if (size + 5 > local->recv_buffer->len) {
                break;
            }
            if (*capacity < datalength + size) {
                *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)((datalength + size) * 2));
                encryptdata = *pencryptdata;
            }
            memcpy(encryptdata + datalength, local->recv_buffer->buffer + 5, size);
            datalength += size;

            buffer_shorten(local->recv_buffer, 5 + size, local->recv_buffer->len - (5 + size));
        }
        return (ssize_t)datalength;
    }
    if (datalength < 11 + 32 + 1 + 32) {
        return -1;
    }
    {
        char hash[SHA1_BYTES];
        BUFFER_CONSTANT_INSTANCE(pClientID, global->local_client_id, 32);
        BUFFER_CONSTANT_INSTANCE(pMsg, encryptdata + 11, 22);
        tls12_sha1_hmac(obfs, pClientID, pMsg, hash);

    if (memcmp(encryptdata + 33, hash, OBFS_HMAC_SHA1_LEN)) {
        return -1;
    }

    *needsendback = 1;
    return 0;
    }
}

bool tls12_ticket_auth_server_pre_encrypt(struct obfs_t *obfs, struct buffer_t *buf) {
    // TODO : need implementation future.
    return generic_server_pre_encrypt(obfs, buf);
}

struct buffer_t * tls12_ticket_auth_server_encode(struct obfs_t *obfs, struct buffer_t *buf) {
    // TODO : need implementation future.
    return generic_server_encode(obfs, buf);
}

struct buffer_t * decode_error_return(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server.g_data;

    local->handshake_status = -1;
    if (obfs->server.overhead > 0) {
        // self.server_info.overhead -= self.overhead
    }
    obfs->server.overhead = 0; // self.overhead = 0
    // if (self.method in ['tls1.2_ticket_auth', 'tls1.2_ticket_fastauth'])
    {
        struct buffer_t *r = buffer_alloc(SSR_BUFF_SIZE);
        if (need_decrypt) { *need_decrypt = false; }
        if (need_feedback) { *need_feedback = false; }
        memset(r->buffer, 'E', SSR_BUFF_SIZE);
        r->len = SSR_BUFF_SIZE;
        return r;
    }
    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

struct buffer_t * tls12_ticket_auth_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    struct tls12_ticket_auth_local_data *local = (struct tls12_ticket_auth_local_data*)obfs->l_data;
    struct tls12_ticket_auth_global_data *global = (struct tls12_ticket_auth_global_data*)obfs->server.g_data;
    struct buffer_t *result = NULL;
    BUFFER_CONSTANT_INSTANCE(empty_buf, "", 0);

    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    if (local->handshake_status == -1) {
        result = buffer_clone(buf);
        return result;
    }
    if ((local->handshake_status & 4) == 4) {
        result = buffer_alloc(SSR_BUFF_SIZE);
        buffer_concatenate2(local->recv_buffer, buf);
        while (local->recv_buffer->len > 5) {
            uint8_t *beginning = local->recv_buffer->buffer;
            size_t size = 0;
            size_t thunk_size = 0;
            if (beginning[0] != 0x17 || beginning[1] != 0x13 || beginning[2] != 0x03) {
                buffer_free(result); result = NULL;
                return result;
            }
            size = (size_t) ntohs( *((uint16_t *)(beginning+3)) ); // uint16_t
            thunk_size = size + 5;
            if (local->recv_buffer->len < thunk_size) {
                break;
            }
            buffer_concatenate(result, beginning + 5, size);

            buffer_shorten(local->recv_buffer, thunk_size, local->recv_buffer->len - thunk_size);
         }
        return result;
    }
    if ((local->handshake_status & 1) == 1) {
        uint8_t *buf_ptr2 = NULL;
        char hash[SHA1_BYTES];
        struct buffer_t *verify = NULL;
        size_t verify_len = 0;
        struct buffer_t *swap = buffer_alloc(SSR_BUFF_SIZE);

        buffer_concatenate2(local->recv_buffer, buf);
        verify = buffer_clone(local->recv_buffer);

        if (local->recv_buffer->len < 11) {
            return NULL;
        }

        // ChangeCipherSpec: b"\x14" + tls_version + b"\x00\x01\x01"
        buffer_reset(swap);
        {
            BUFFER_CONSTANT_INSTANCE(const_buff1, "\x14", 1);
            BUFFER_CONSTANT_INSTANCE(const_buff2, "\x00\x01\x01", 3);
            buffer_concatenate2(swap, const_buff1);
            buffer_concatenate2(swap, tls_version);
            buffer_concatenate2(swap, const_buff2);
        }
        if (memcmp(local->recv_buffer->buffer, swap->buffer, swap->len) != 0) {
            return NULL;
        }

        buf_ptr2 = local->recv_buffer->buffer + swap->len; // buf = buf[6:]

        // Finished: b"\x16" + tls_version + b"\x00"
        buffer_reset(swap);
        {
            BUFFER_CONSTANT_INSTANCE(const_buff1, "\x16", 1);
            BUFFER_CONSTANT_INSTANCE(const_buff2, "\x00", 1);
            buffer_concatenate2(swap, const_buff1);
            buffer_concatenate2(swap, tls_version);
            buffer_concatenate2(swap, const_buff2);
        }
        if (memcmp(buf_ptr2, swap->buffer, swap->len) != 0) {
            return NULL;
        }

        verify_len = (size_t) ntohs(*((uint16_t *)(buf_ptr2+3))) + 1; // 11-10
        if (verify->len < (verify_len + 10)) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            return buffer_alloc(SSR_BUFF_SIZE);
        }
        {
            BUFFER_CONSTANT_INSTANCE(pMsg, verify->buffer, verify_len);
            tls12_sha1_hmac(obfs, local->client_id, pMsg, hash);
        }
        if (memcmp(hash, verify->buffer+verify_len, OBFS_HMAC_SHA1_LEN) != 0) {
            return NULL;
        }

        verify_len = verify_len + OBFS_HMAC_SHA1_LEN;
        buffer_store(local->recv_buffer, verify->buffer + verify_len, verify->len - verify_len);

        buffer_free(verify);
        buffer_free(swap);

        local->handshake_status |= 4;

        return tls12_ticket_auth_server_decode(obfs, empty_buf, need_decrypt, need_feedback);
    }
    {
        struct buffer_t *buf_copy = NULL;
        struct buffer_t *ogn_buf = NULL;
        struct buffer_t *verifyid = NULL;
        struct buffer_t *sessionid = NULL;
        char sha1[SHA1_BYTES] = { 0 };
        size_t header_len = 0;
        size_t msg_size = 0;
        size_t sessionid_len = 0;
        uint32_t utc_time = 0;
        uint32_t time_dif = 0;

        buffer_concatenate2(local->recv_buffer, buf);
        buf_copy = buffer_clone(local->recv_buffer);
        ogn_buf = buffer_clone(local->recv_buffer);
        if (buf_copy->len < 3) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            return buffer_clone(empty_buf);
        }
        if (memcmp(buf_copy, "\x16\x03\x01", 3) != 0) {
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        buffer_shorten(buf_copy, 3, buf_copy->len - 3);
        header_len = (size_t) ntohs(*((uint16_t *)buf_copy->buffer));
        if (header_len > (buf_copy->len - sizeof(uint16_t))) {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = false; }
            return buffer_clone(empty_buf);
        }
        buffer_shorten(local->recv_buffer, header_len+5, local->recv_buffer->len - (header_len + 5));
        local->handshake_status = 1;
        buffer_shorten(buf_copy, 2, header_len);
        if (memcmp(buf_copy->buffer, "\x01\x00", 2) != 0) {
            // logging.info("tls_auth not client hello message")
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        buffer_shorten(buf_copy, 2, buf_copy->len - 2);
        msg_size = (size_t) ntohs(*((uint16_t *)buf_copy->buffer));
        if (msg_size != buf_copy->len - 2) {
            // logging.info("tls_auth wrong message size")
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        buffer_shorten(buf_copy, 2, buf_copy->len - 2);
        if (memcmp(buf_copy->buffer, tls_version->buffer, 2) != 0) {
            // logging.info("tls_auth wrong tls version")
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        buffer_shorten(buf_copy, 2, buf_copy->len - 2);
        verifyid = buffer_create_from(buf_copy->buffer, 32);
        buffer_shorten(buf_copy, 32, buf_copy->len - 32);
        sessionid_len = (size_t) buf_copy->buffer[0];
        if (sessionid_len < 32) {
            // logging.info("tls_auth wrong sessionid_len")
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        sessionid = buffer_create_from(buf_copy->buffer, sessionid_len);
        buffer_shorten(buf_copy, sessionid_len + 1, buf_copy->len - (sessionid_len + 1));
        buffer_replace(local->client_id, sessionid);
        {
            BUFFER_CONSTANT_INSTANCE(pMsg, verifyid->buffer, 22);
            tls12_sha1_hmac(obfs, local->client_id, pMsg, sha1);
        }
        utc_time = (uint32_t) ntohl(*(uint32_t *)verifyid->buffer);
        time_dif = (uint32_t)(time(NULL) & 0xffffffff) - utc_time;
        //if (obfs->server.param) {
        //    // self.max_time_dif = int(self.server_info.obfs_param)
        //    local->max_time_dif = obfs->server.param;
        //}
        //if self.max_time_dif > 0 and (time_dif < -self.max_time_dif or time_dif > self.max_time_dif \
        //        or common.int32(utc_time - self.server_info.data.startup_time) < -self.max_time_dif / 2):
        //    logging.info("tls_auth wrong time")
        //    return self.decode_error_return(ogn_buf)
        if (memcmp(sha1, verifyid->buffer+22, 10) != 0) {
            // logging.info("tls_auth wrong sha1")
            return decode_error_return(obfs, ogn_buf, need_decrypt, need_feedback);
        }
        //if self.server_info.data.client_data.get(verifyid[:22]):
        //    logging.info("replay attack detect, id = %s" % (binascii.hexlify(verifyid)))
        //    return self.decode_error_return(ogn_buf)
        //self.server_info.data.client_data.sweep()
        //self.server_info.data.client_data[verifyid[:22]] = sessionid
        if (local->recv_buffer->len >= 11) {
            struct buffer_t *ret =
                tls12_ticket_auth_server_decode(obfs, empty_buf, need_decrypt, need_feedback);
            if (need_decrypt) { *need_decrypt = true; }
            if (need_feedback) { *need_feedback = true; }
            return ret;
        } else {
            if (need_decrypt) { *need_decrypt = false; }
            if (need_feedback) { *need_feedback = true; }
            return buffer_clone(empty_buf);
        }
    }
}

bool tls12_ticket_auth_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *flag) {
    // TODO : need implementation future.
    return generic_server_post_decrypt(obfs, buf, flag);
}

bool tls12_ticket_auth_server_udp_pre_encrypt(struct obfs_t *obfs, struct buffer_t *buf) {
    // TODO : need implementation future.
    return generic_server_udp_pre_encrypt(obfs, buf);
}

bool tls12_ticket_auth_server_udp_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, uint32_t *uid) {
    // TODO : need implementation future.
    return generic_server_udp_post_decrypt(obfs, buf, uid);
}


//============================= tls1.2_ticket_fastauth ==================================

void * tls12_ticket_fastauth_init_data(void) {
    return tls12_ticket_auth_init_data();
}

struct obfs_t * tls12_ticket_fastauth_new_obfs(void) {
    struct obfs_t *obfs = tls12_ticket_auth_new_obfs();
    ((struct tls12_ticket_auth_local_data*)obfs->l_data)->fastauth = true;
    return obfs;
}

int tls12_ticket_fastauth_get_overhead(struct obfs_t *obfs) {
    return tls12_ticket_auth_get_overhead(obfs);
}

void tls12_ticket_fastauth_dispose(struct obfs_t *obfs) {
    tls12_ticket_auth_dispose(obfs);
}

size_t tls12_ticket_fastauth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity) {
    return tls12_ticket_auth_client_encode(obfs, pencryptdata, datalength, capacity);
}

ssize_t tls12_ticket_fastauth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback) {
    return tls12_ticket_auth_client_decode(obfs, pencryptdata, datalength, capacity, needsendback);
}
