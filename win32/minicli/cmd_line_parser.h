//
// Created by ssrlive on 18-4-22.
//

#ifndef __SSR_NATIVE_CMD_LINE_H__
#define __SSR_NATIVE_CMD_LINE_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cmd_line_info {
    char *server_addr;
    char *server_port;
    char *request_page;
    char *root_cert_file;
    int dump_level;
    bool help_flag;
};

struct cmd_line_info * cmd_line_info_create(int argc, char * const argv[]);
void cmd_line_info_destroy(struct cmd_line_info *info);
const char * app_name(const char *app_path);
int usage(int argc, char * const argv[]);

#ifdef __cplusplus
}
#endif

#endif // __SSR_NATIVE_CMD_LINE_H__
