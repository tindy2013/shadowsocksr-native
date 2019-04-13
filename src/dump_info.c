#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "dump_info.h"
#include "text_in_color.h"

char progname[512 + 1] = __FILE__;  /* Reset in main(). */

void set_app_name(const char *name) {
    strcpy(progname, name);
}

const char *get_app_name(void) {
    const char *name = NULL;
#if defined(_MSC_VER)
    name = strrchr(progname, '\\');
#else
    name = strrchr(progname, '/');
#endif // defined(_MSC_VER)
    return name ? name + 1 : progname;
}

void(*info_callback)(const char *info, void *p) = NULL;
void *info_callback_p = NULL;

void set_dump_info_callback(void(*callback)(const char *info, void *p), void *p) {
    info_callback = callback;
    info_callback_p = p;
}

#define DUMP_LEVEL_MAP(V)                                   \
    V( dump_level_info,     " info",    text_color_white)   \
    V( dump_level_warn,     " warn",    text_color_yellow)  \
    V( dump_level_error,    "error",    text_color_red)     \

typedef enum dump_level {
#define DUMP_LEVEL_GEN(item, info_text, _) item,
    DUMP_LEVEL_MAP(DUMP_LEVEL_GEN)
#undef DUMP_LEVEL_GEN
    dump_level_max,
} dump_level;

static void pr_do(FILE *stream, dump_level level, const char *fmt, va_list ap);

void pr_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stdout, dump_level_info, fmt, ap);
    va_end(ap);
}

void pr_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, dump_level_warn, fmt, ap);
    va_end(ap);
}

void pr_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, dump_level_error, fmt, ap);
    va_end(ap);
}

static void pr_do(FILE *stream, dump_level level, const char *fmt, va_list ap) {
    static const int size = 1024;
    char *fmtbuf = (char *) calloc(size, sizeof(fmtbuf[0]));
    char *p;
    const char *label = NULL;
    enum text_color color = text_color_white;
    vsnprintf(fmtbuf, size, fmt, ap);
    p = (char *) calloc(size * 2, sizeof(*p));

#define DUMP_LEVEL_ENUM(item, info_text, txt_color) case (item): label = (info_text); color=txt_color; break;
    switch (level) {
        DUMP_LEVEL_MAP(DUMP_LEVEL_ENUM)
    default:;  // Silence dump_level_max -Wswitch warning.
    }
#undef DUMP_LEVEL_ENUM

    if (info_callback) {
        sprintf(p, "%s:%s: %s\n", get_app_name(), label, fmtbuf);
        info_callback(p, info_callback_p);
    } else {
        fprintf(stream, "%s:%s: ", get_app_name(), label);
        sprintf(p, "%s\n", fmtbuf);
        print_text_in_color(stream, p, color);
    }
    free(p);
    free(fmtbuf);
}
