#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "dump_info.h"

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

static void pr_do(FILE *stream, const char *label, const char *fmt, va_list ap);

void pr_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stdout, "info", fmt, ap);
    va_end(ap);
}

void pr_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "warn", fmt, ap);
    va_end(ap);
}

void pr_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "error", fmt, ap);
    va_end(ap);
}

static void pr_do(FILE *stream, const char *label, const char *fmt, va_list ap) {
    static const int size = 1024;
    char *fmtbuf = (char *) calloc(size, sizeof(fmtbuf[0]));
    vsnprintf(fmtbuf, size, fmt, ap);
    if (info_callback) {
        char *p = (char *) calloc(size * 2, sizeof(*p));
        sprintf(p, "%s:%s: %s\n", get_app_name(), label, fmtbuf);
        info_callback(p, info_callback_p);
        free(p);
    } else {
        fprintf(stream, "%s:%s: %s\n", get_app_name(), label, fmtbuf);
    }
    free(fmtbuf);
}
