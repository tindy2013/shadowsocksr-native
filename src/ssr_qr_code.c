
#include "base64.h"
#include "ssrcipher.h"

char * ssr_qr_code_encode(const struct server_config *config, void*(*alloc_fn)(size_t size)) {
    if (config==NULL || alloc_fn==NULL) {
        return NULL;
    }

    if (config->remote_host == NULL ||
        config->remote_port == 0 ||
        config->method == NULL ||
        config->password == NULL ||
        config->protocol == NULL ||
        config->obfs == NULL) {
        return NULL;
    }

    // ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0)

    unsigned char *base64_buf = (unsigned char *)calloc(SSR_BUFF_SIZE, sizeof(base64_buf[0]));

    char *basic = (char *)calloc(SSR_BUFF_SIZE, sizeof(basic[0]));

    url_safe_base64_encode((unsigned char *)config->password, (int)strlen(config->password), base64_buf);
    sprintf(basic, "%s:%d:%s:%s:%s:%s",
            config->remote_host, config->remote_port,
            config->protocol, config->method, config->obfs,
            base64_buf);

    char *optional = (char *)calloc(SSR_BUFF_SIZE, sizeof(optional[0]));
    static const char *fmt0 = "%s=%s";
    static const char *fmt1 = "&%s=%s";

    if ((config->obfs_param != NULL) && (strlen(config->obfs_param) != 0)) {
        size_t len = strlen(optional);
        memset(base64_buf, 0, SSR_BUFF_SIZE*sizeof(base64_buf[0]));
        url_safe_base64_encode((unsigned char *)config->obfs_param, (int)strlen(config->obfs_param), base64_buf);
        sprintf(optional+len, len?fmt1:fmt0, "obfsparam", base64_buf);
    }
    if ((config->protocol_param != NULL) && (strlen(config->protocol_param) != 0)) {
        size_t len = strlen(optional);
        memset(base64_buf, 0, SSR_BUFF_SIZE*sizeof(base64_buf[0]));
        url_safe_base64_encode((unsigned char *)config->protocol_param, (int)strlen(config->protocol_param), base64_buf);
        sprintf(optional+len, len?fmt1:fmt0, "protoparam", base64_buf);
    }
    if ((config->remarks != NULL) && (strlen(config->remarks) != 0)) {
        size_t len = strlen(optional);
        memset(base64_buf, 0, SSR_BUFF_SIZE*sizeof(base64_buf[0]));
        url_safe_base64_encode((unsigned char *)config->remarks, (int)strlen(config->remarks), base64_buf);
        sprintf(optional+len, len?fmt1:fmt0, "remarks", base64_buf);
    }
    // config->group
    // config->udpport
    // config->uot

    char *result = (char *)alloc_fn(SSR_BUFF_SIZE * sizeof(result[0]));
    sprintf(result, strlen(optional) ? "%s/?%s" : "%s/%s", basic, optional);
    
    memset(base64_buf, 0, SSR_BUFF_SIZE*sizeof(base64_buf[0]));
    url_safe_base64_encode((unsigned char *)result, (int)strlen(result), base64_buf);

    sprintf(result, "ssr://%s", base64_buf);
    
    free(base64_buf);
    free(basic);
    free(optional);

    return result;
}
