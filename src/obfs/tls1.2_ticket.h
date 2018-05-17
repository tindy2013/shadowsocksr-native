/*
 * tls1.2_ticket.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2017, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_TLS1_2_TICKET_H
#define _OBFS_TLS1_2_TICKET_H

void * tls12_ticket_auth_init_data(void);
struct obfs_t * tls12_ticket_auth_new_obfs(void);
void tls12_ticket_auth_dispose(struct obfs_t *obfs);

size_t tls12_ticket_auth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity);
ssize_t tls12_ticket_auth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback);

int tls12_ticket_auth_get_overhead(struct obfs_t *obfs);

struct buffer_t * tls12_ticket_auth_server_pre_encrypt(struct obfs_t *obfs, struct buffer_t *buf);
struct buffer_t * tls12_ticket_auth_server_encode(struct obfs_t *obfs, struct buffer_t *buf);
struct buffer_t * tls12_ticket_auth_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);
struct buffer_t * tls12_ticket_auth_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);
bool tls12_ticket_auth_server_udp_pre_encrypt(struct obfs_t *obfs, struct buffer_t *buf);
bool tls12_ticket_auth_server_udp_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, uint32_t *uid);

//============================= tls1.2_ticket_fastauth ==================================

void * tls12_ticket_fastauth_init_data(void);
struct obfs_t * tls12_ticket_fastauth_new_obfs(void);
int tls12_ticket_fastauth_get_overhead(struct obfs_t *obfs);
void tls12_ticket_fastauth_dispose(struct obfs_t *obfs);
size_t tls12_ticket_fastauth_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity);
ssize_t tls12_ticket_fastauth_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback);


#endif // _OBFS_TLS1_2_TICKET_H
