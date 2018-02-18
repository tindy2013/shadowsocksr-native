/*
 * udprelay.h - Define UDP relay's buffers and callbacks
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <uv.h>

struct ss_host_port;
struct udp_server_ctx_t;
struct cipher_env_t;

struct udp_server_ctx_t * udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
#ifdef MODULE_LOCAL
    const struct sockaddr *remote_addr, const int remote_addr_len,
    const struct ss_host_port *tunnel_addr,
#endif
    int mtu, int timeout, const char *iface, struct cipher_env_t *cipher_env,
    const char *protocol, const char *protocol_param);

void udprelay_shutdown(struct udp_server_ctx_t *server_ctx);

#endif // _UDPRELAY_H
