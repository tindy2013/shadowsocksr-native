#ifndef __LOCAL_CONFIG_H__
#define __LOCAL_CONFIG_H__

#include <string.h>
#include <stdlib.h>

struct ss_host_port;
struct server_config;
struct ssr_local_state;

struct local_config_t {
    char * timeout;
    char * iface;
    int mptcp;
    int remote_num;
    struct ss_host_port *remote_addr;
    char **hostnames;
    char *remote_port;

    char *local_addr;
    char *local_port;

    int mode;
    int mtu;
    char *user;
    
    char *method;
    char *password;
    char *protocol;
    char *protocol_param;
    char *obfs;
    char *obfs_param;
};

int ssr_local_main_loop(const struct local_config_t *config, void(*feedback_state)(struct ssr_local_state *state, void *p), void *p);
void local_config_release(struct local_config_t *config);
int ssr_Local_listen_socket_fd(struct ssr_local_state *state);

struct local_config_t * server_config_to_local_config(struct server_config *svr_cgf);


#endif // __LOCAL_CONFIG_H__
