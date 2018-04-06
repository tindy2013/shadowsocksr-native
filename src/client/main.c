/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_json.h"
#include "dump_info.h"
#include "common.h"
#include "ssr_executive.h"
#include "ssr_client_api.h"

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

static const char * parse_opts(int argc, char **argv);
static void usage(void);

struct ssr_client_state *g_state = NULL;
void feedback_state(struct ssr_client_state *state, void *p);
void print_remote_info(const struct server_config *config);

int main(int argc, char **argv) {
    struct server_config *config = NULL;
    int err = -1;
    const char *config_path = NULL;

    do {
        set_app_name(argv[0]);

        config_path = DEFAULT_CONF_PATH;
        if (argc > 1) {
            config_path = parse_opts(argc, argv);
        }

        if (config_path == NULL) {
            break;
        }

        config = config_create();
        if (parse_config_file(config_path, config) == false) {
            break;
        }

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password==NULL || config->remote_host==NULL) {
            break;
        }

        print_remote_info(config);

        ssr_run_loop_begin(config, &feedback_state, NULL);
        g_state = NULL;

        err = 0;
    } while(0);

    config_release(config);

    if (err != 0) {
        usage();
    }

    return 0;
}

void print_remote_info(const struct server_config *config) {
    char remote_host[256] = { 0 };
    strcpy(remote_host, config->remote_host);
    if (strlen(remote_host) > 4) {
        size_t i = 0;
        for (i = 4; i < strlen(remote_host); i++) {
            remote_host[i] = '*';
        }
    }

    char password[256] = { 0 };
    strcpy(password, config->password);
    if (strlen(password) > 2) {
        size_t i = 0;
        for (i = 2; i < strlen(password); i++) {
            password[i] = '*';
        }
    }

    pr_info("ShadowsocksR native client\n");
    pr_info("remote server    %s:%hu", remote_host, config->remote_port);
    pr_info("method           %s", config->method);
    pr_info("password         %s", password);
    pr_info("protocol         %s", config->protocol);
    if (config->protocol_param && strlen(config->protocol_param)) {
        pr_info("protocol_param   %s", config->protocol_param);
    }
    pr_info("obfs             %s", config->obfs);
    if (config->obfs_param && strlen(config->obfs_param)) {
        pr_info("obfs_param       %s", config->obfs_param);
    }
    pr_info("udp relay        %s\n", config->udp ? "yes" : "no");
}

void feedback_state(struct ssr_client_state *state, void *p) {
    g_state = state;
    (void)p;
}

static const char * parse_opts(int argc, char **argv) {
    int opt;

    while (-1 != (opt = getopt(argc, argv, "c:h"))) {
        switch (opt) {
        case 'c':
            return optarg;
            break;
        case 'h':
        default:
            break;
        }
    }
    return NULL;
}

static void usage(void) {
    printf("ShadowsocksR native client\n"
        "\n"
        "Usage:\n"
        "\n"
        "  %s [-c <config file>] [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -c <config file>       Configure file path.\n"
        "                         Default: " DEFAULT_CONF_PATH "\n"
        "  -h                     Show this help message.\n"
        "",
        get_app_name());
    exit(1);
}
