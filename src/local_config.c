#include <string.h>
#include <stdlib.h>

#include "local_config.h"
#include "ssr_executive.h"
#include "jconf.h"
#include "common.h"

void local_config_release(struct local_config_t *config) {
    if (config == NULL) {
        return;
    }
    object_safe_free((void **)&config->timeout);
    object_safe_free((void **)&config->iface);

    if (config->remote_num) {
        int index = 0;
        ASSERT(config->hostnames);
        ASSERT(config->remote_addr);

        for (index=0; index<config->remote_num; ++index) {
            object_safe_free((void **)&config->remote_addr[index].host);
            object_safe_free((void **)&config->remote_addr[index].port);
        }
        object_safe_free((void **)&config->remote_addr);

        for (index=0; index<config->remote_num; ++index) {
            object_safe_free((void **)&config->hostnames[index]);
            object_safe_free((void **)&config->hostnames[index]);
        }
        object_safe_free((void **)&config->hostnames);
    }

    object_safe_free((void **)&config->remote_port);

    object_safe_free((void **)&config->local_addr);
    object_safe_free((void **)&config->local_port);

    object_safe_free((void **)&config->user);

    object_safe_free((void **)&config->method);
    object_safe_free((void **)&config->password);
    object_safe_free((void **)&config->protocol);
    object_safe_free((void **)&config->protocol_param);
    object_safe_free((void **)&config->obfs);
    object_safe_free((void **)&config->obfs_param);
}

struct local_config_t * server_config_to_local_config(struct server_config *svr_cgf) {
    char swap_buff[257] = { 0 };
    struct local_config_t *local_config = (struct local_config_t *)calloc(1, sizeof(*local_config));

    sprintf(swap_buff, "%d", svr_cgf->idle_timeout);
    string_safe_assign(&local_config->timeout, swap_buff);

    int remote_num = 1;
    local_config->remote_num = remote_num;
    {
        int index = 0;
        local_config->remote_addr = (struct ss_host_port *)calloc(remote_num, sizeof(struct ss_host_port));
        for (index=0; index<remote_num; ++index) {
            string_safe_assign(&local_config->remote_addr[index].host, svr_cgf->remote_host);
        }
    }

    sprintf(swap_buff, "%d", svr_cgf->remote_port);
    string_safe_assign(&local_config->remote_port, swap_buff);

    local_config->mode = svr_cgf->udp ? 0 : 1; // TCP_AND_UDP

    string_safe_assign(&local_config->local_addr, svr_cgf->listen_host);

    sprintf(swap_buff, "%d", svr_cgf->listen_port);
    string_safe_assign(&local_config->local_port, swap_buff);

    string_safe_assign(&local_config->method, svr_cgf->method);
    string_safe_assign(&local_config->password, svr_cgf->password);
    string_safe_assign(&local_config->protocol, svr_cgf->protocol);
    string_safe_assign(&local_config->protocol_param, svr_cgf->protocol_param);
    string_safe_assign(&local_config->obfs, svr_cgf->obfs);
    string_safe_assign(&local_config->obfs_param, svr_cgf->obfs_param);

    return local_config;
}
