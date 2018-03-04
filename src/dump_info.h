#if !defined(__dump_info_h__)
#define __dump_info_h__ 1

void set_app_name(const char *name);
const char *get_app_name(void);

#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);

#endif // !defined(__dump_info_h__)
