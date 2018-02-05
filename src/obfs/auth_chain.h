/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_CHAIN_H
#define _OBFS_AUTH_CHAIN_H

void * auth_chain_a_init_data(void);
void * auth_chain_b_init_data(void);
void * auth_chain_c_init_data(void);
void * auth_chain_d_init_data(void);
void * auth_chain_e_init_data(void);

struct obfs_t * auth_chain_a_new_obfs(void);
struct obfs_t * auth_chain_b_new_obfs(void);
struct obfs_t * auth_chain_c_new_obfs(void);
struct obfs_t * auth_chain_d_new_obfs(void);
struct obfs_t * auth_chain_e_new_obfs(void);

void auth_chain_a_dispose(struct obfs_t *obfs);
void auth_chain_b_dispose(struct obfs_t *obfs);
void auth_chain_c_dispose(struct obfs_t *obfs);
void auth_chain_d_dispose(struct obfs_t *obfs);
void auth_chain_e_dispose(struct obfs_t *obfs);

void auth_chain_a_set_server_info(struct obfs_t *obfs, struct server_info_t *server);
void auth_chain_b_set_server_info(struct obfs_t *obfs, struct server_info_t *server);
void auth_chain_c_set_server_info(struct obfs_t *obfs, struct server_info_t *server);
void auth_chain_d_set_server_info(struct obfs_t *obfs, struct server_info_t *server);
void auth_chain_e_set_server_info(struct obfs_t *obfs, struct server_info_t *server);

int auth_chain_a_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
ssize_t auth_chain_a_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_chain_a_client_udp_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_chain_a_client_udp_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_chain_a_get_overhead(struct obfs_t *obfs);
int auth_chain_b_get_overhead(struct obfs_t *self);
int auth_chain_c_get_overhead(struct obfs_t *obfs);
int auth_chain_d_get_overhead(struct obfs_t *self);
int auth_chain_e_get_overhead(struct obfs_t *self);

#endif // _OBFS_AUTH_CHAIN_H
