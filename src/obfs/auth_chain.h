/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_CHAIN_H
#define _OBFS_AUTH_CHAIN_H

struct obfs_t;

//============================= auth_chain_a ==================================
void auth_chain_a_new_obfs(struct obfs_t *obfs);

//============================= auth_chain_b ==================================
void auth_chain_b_new_obfs(struct obfs_t *obfs);

//============================= auth_chain_c ==================================
void auth_chain_c_new_obfs(struct obfs_t *obfs);

//============================= auth_chain_d ==================================
void auth_chain_d_new_obfs(struct obfs_t *obfs);

//============================= auth_chain_e ==================================
void auth_chain_e_new_obfs(struct obfs_t *obfs);

//============================= auth_chain_f ==================================
void auth_chain_f_new_obfs(struct obfs_t *obfs);


#endif // _OBFS_AUTH_CHAIN_H
