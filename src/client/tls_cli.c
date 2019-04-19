#include <mbedtls/config.h>
#include <mbedtls/platform.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include "cmd_line_parser.h"
#include "dump_info.h"
#include "ssr_executive.h"
#include "tunnel.h"
#include "tls_cli.h"
#include "ssrbuffer.h"
#include <uv.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GET_REQUEST_FORMAT ""                                                               \
    "POST %s HTTP/1.1\r\n"                                                                  \
    "Host: %s:%d\r\n"                                                                       \
    "User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"     \
    "Accept: text/html,application/xhtml+xml,application/octet-stream;q=0.9,*/*;q=0.8\r\n"  \
    "Accept-Language: en-US,en;q=0.5\r\n"                                                   \
    "Accept-Encoding: gzip, deflate\r\n"                                                    \
    "Connection: keep-alive\r\n"                                                            \
    "Upgrade-Insecure-Requests: 1\r\n"                                                      \
    "Content-Type: application/octet-stream\r\n"                                            \
    "Content-Length: %d\r\n\r\n"                                                            \


#define GET_REQUEST_END "\r\n\r\n"

#define ALPN_LIST_SIZE  10
#define DFL_PSK_IDENTITY "Client_identity"
#define MAX_REQUEST_SIZE      20000
#define DFL_REQUEST_SIZE        -1
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM

struct tls_cli_ctx {
    struct uv_work_s *req;
    struct uv_async_s *async;
    struct tunnel_ctx *tunnel; /* weak pointer */
    struct server_config *config; /* weak pointer */
    mbedtls_ssl_context *ssl_ctx; /* weak pointer */
};

struct tls_cli_ctx * create_tls_cli_ctx(struct tunnel_ctx *tunnel, struct server_config *config);
void destroy_tls_cli_ctx(struct tls_cli_ctx *ctx);


struct tls_cli_ctx * create_tls_cli_ctx(struct tunnel_ctx *tunnel, struct server_config *config) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)calloc(1, sizeof(*ctx));
    ctx->req = (struct uv_work_s *)calloc(1, sizeof(*ctx->req));
    ctx->req->data = ctx;
    ctx->async = (struct uv_async_s *)calloc(1, sizeof(*ctx->async));
    ctx->tunnel = tunnel;
    ctx->config = config;
    return ctx;
}

void destroy_tls_cli_ctx(struct tls_cli_ctx *ctx) {
    if (ctx) {
        free(ctx->req);
        free(ctx->async);
        free(ctx);
    }
}

void tls_cli_main_callback(uv_work_t *req);
static bool tls_cli_send_data(mbedtls_ssl_context *ssl_ctx,
    const char *url_path, const char *domain, unsigned short domain_port,
    uint8_t *data, size_t size);
static void tls_cli_remote_data_coming_cb(uv_async_t *handle);
static void tls_cli_after_cb(uv_work_t *req, int status);
static void tls_async_send_incoming_data(struct tls_cli_ctx *ctx, const uint8_t *buf, size_t len);

struct tls_data_arrival {
    struct buffer_t *data;
    struct tls_cli_ctx *ctx;
};

void tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config) {
    uv_loop_t *loop = tunnel->listener->loop;
    struct tls_cli_ctx *ctx = create_tls_cli_ctx(tunnel, config);

    uv_async_init(loop, ctx->async, tls_cli_remote_data_coming_cb);
    uv_queue_work(loop, ctx->req, tls_cli_main_callback, tls_cli_after_cb);
}

void tls_cli_main_callback(uv_work_t* req) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)req->data;
    struct server_config *config = ctx->config;

    int ret = 0, len, proto;
    mbedtls_net_context connect_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    char *alpn_list[ALPN_LIST_SIZE] = { NULL };
    const char *pers = get_app_name();
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char psk[MBEDTLS_PSK_MAX_LEN];
    size_t psk_len = 0;
#endif
#if defined(MBEDTLS_TIMING_C)
    mbedtls_timing_delay_context timer = { 0 };
#endif
    uint32_t flags;
    unsigned char buf[MAX_REQUEST_SIZE + 1];
    int request_size = DFL_REQUEST_SIZE;
    int transport = DFL_TRANSPORT; /* TCP only, UDP not supported */
    char *port = NULL;

    mbedtls_net_init( &connect_ctx );
    mbedtls_ssl_init( &ssl_ctx );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );
    mbedtls_pk_init( &pkey );

    mbedtls_debug_set_threshold( 1 ); /* Error level */

    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
        &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }
    if (config->over_tls_root_cert_file) {
        ret = mbedtls_x509_crt_parse_file(&cacert, config->over_tls_root_cert_file);
    }

    ret = mbedtls_x509_crt_parse( &clicert,
        (const unsigned char *) mbedtls_test_cli_crt,
        mbedtls_test_cli_crt_len );

    ret = mbedtls_pk_parse_key(&pkey,
        (const unsigned char *)mbedtls_test_cli_key,
        mbedtls_test_cli_key_len, NULL, 0 );


    port = itoa(config->remote_port, (char *)buf, sizeof(buf));
    mbedtls_printf("  . Connecting to %s/%s/%s...",
        transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "tcp" : "udp",
        config->remote_host, port);
    fflush( stdout );

    proto = (transport == MBEDTLS_SSL_TRANSPORT_STREAM) ? MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP;
    ret = mbedtls_net_connect(&connect_ctx, config->remote_host, port, proto);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_net_set_nonblock(&connect_ctx)) != 0) {
        mbedtls_printf(" failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
        goto exit;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, transport, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    // mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_ssl_conf_read_timeout(&conf, 0 /* opt.read_timeout */);

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets(&conf, 1 /* opt.tickets */);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation( &conf, 1 /* opt.renegotiation */);
#endif

    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    ret = mbedtls_ssl_conf_psk(&conf, psk, psk_len, (const unsigned char *)DFL_PSK_IDENTITY, strlen(DFL_PSK_IDENTITY));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_psk returned %d\n\n", ret);
        goto exit;
    }
#endif

    if (config->over_tls_root_cert_file) {
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    }

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if ((ret = mbedtls_ssl_set_hostname(&ssl_ctx, config->remote_host)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }
#endif

    mbedtls_ssl_set_bio(&ssl_ctx, &connect_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

#if defined(MBEDTLS_TIMING_C)
    mbedtls_ssl_set_timer_cb(&ssl_ctx, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
#endif

    while ((ret = mbedtls_ssl_handshake(&ssl_ctx)) != 0) {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
            ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
                mbedtls_printf(
                "    Unable to verify the server's certificate. "
                "Either it is invalid,\n"
                "    or you didn't set ca_file or ca_path "
                "to an appropriate value.\n"
                "    Alternatively, you may want to use "
                "auth_mode=optional for testing purposes.\n" );
            mbedtls_printf( "\n" );
            goto exit;
        }

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if( ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS ) {
            continue;
        }
#endif
    }

    mbedtls_printf(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
        mbedtls_ssl_get_version(&ssl_ctx),
        mbedtls_ssl_get_ciphersuite(&ssl_ctx));

    if ((ret = mbedtls_ssl_get_record_expansion(&ssl_ctx)) >= 0) {
        mbedtls_printf("    [ Record expansion is %d ]\n", ret );
    } else {
        mbedtls_printf("    [ Record expansion is unknown (compression) ]\n");
    }
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_printf("    [ Maximum fragment length is %u ]\n",
        (unsigned int)mbedtls_ssl_get_max_frag_len(&ssl_ctx));
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /* 5. Verify the server certificate */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_ctx)) != 0) {
        char vrfy_buf[512] = { 0 };
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf );
    } else {
        mbedtls_printf(" ok\n");
    }
    if (mbedtls_ssl_get_peer_cert(&ssl_ctx) != NULL) {
        mbedtls_printf( "  . Peer certificate information    ...\n" );
        mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                       mbedtls_ssl_get_peer_cert( &ssl_ctx ) );
        mbedtls_printf( "%s\n", buf );
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    ctx->ssl_ctx = &ssl_ctx;

    /* 6. Write the GET request */
    if (tls_cli_send_data(ctx->ssl_ctx, config->over_tls_path, config->over_tls_server_domain, config->remote_port, buf, 0) == false) {
        goto exit;
    }

    /* 7. Read the HTTP response */
    mbedtls_printf("  < Read from server:");
    fflush( stdout );

    /* TLS and DTLS need different reading styles (stream vs datagram) */
    if (transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
        do {
            len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl_ctx, buf, len);

#if defined(MBEDTLS_ECP_RESTARTABLE)
            if (ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
                continue;
            }
#endif
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret <= 0) {
                switch (ret){
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    ret = 0;
                    goto close_notify;
                case 0:
                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    ret = 0;
                    goto reconnect;
                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    goto exit;
                }
            }

            len = ret;
            buf[len] = '\0';
#if 0
            mbedtls_printf(" %d bytes read\n\n%s", len, (char *)buf);
#else
            tls_async_send_incoming_data(ctx, buf, len);
#endif
            /* End of message should be detected according to the syntax of the
             * application protocol (eg HTTP), just use a dummy test here. */
            if (ret > 0 && buf[len-1] == '\n') {
                ret = 0;
                break;
            }
        } while(1);
    }
    else {
        /* Not stream, so datagram, omitted by us */
    }

    /* 8. Done, cleanly close the connection */
close_notify:
    mbedtls_printf("  . Closing the connection...");
    fflush(stdout);

    /* No error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify(&ssl_ctx);
    } while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    mbedtls_printf( " done\n" );

    /* 9. Reconnect? */
reconnect: ;

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100] = { 0 };
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: -0x%X - %s\n\n", -ret, error_buf);
    }
#endif

    mbedtls_net_free( &connect_ctx );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free( &clicert );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_pk_free( &pkey );
#endif
    mbedtls_ssl_free( &ssl_ctx );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout); getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if (ret < 0) {
        ret = 1;
    }
    // return ret;
}

static bool tls_cli_send_data(mbedtls_ssl_context *ssl_ctx,
    const char *url_path,
    const char *domain,
    unsigned short domain_port,
    uint8_t *data, size_t size)
{
    int len, written, frags, ret;
    uint8_t *buf = (uint8_t *)calloc(MAX_REQUEST_SIZE + 1, sizeof(*buf));
    bool result = false;

    len = mbedtls_snprintf((char *)buf, MAX_REQUEST_SIZE, GET_REQUEST_FORMAT,
        url_path, domain, domain_port, size);

    if (data && size) {
        memcpy(buf + len, data, size);
        len += (int)size;
    }

    {
        written = 0;
        frags = 0;

        do {
            while ((ret = mbedtls_ssl_write(ssl_ctx, buf + written, len - written)) < 0) {
                if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
                    ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
                {
                    mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
                    goto exit;
                }
            }
            frags++;
            written += ret;
        } while (written < len);
        result = true;
    }

    buf[written] = '\0';
    mbedtls_printf(" %d bytes written in %d fragments\n\n%s\n", written, frags, (char *)buf);
exit:
    free(buf);
    return result;
}

static void tls_cli_remote_data_coming_cb(uv_async_t *handle) {
    /* this point is in event-loop thread */
    struct tls_data_arrival *data_arrival = (struct tls_data_arrival *)handle->data;
    struct buffer_t *data = data_arrival->data;
    struct tls_cli_ctx *ctx = data_arrival->ctx;
    struct tunnel_ctx *tunnel = ctx->tunnel;

    free(data_arrival);
    if (tunnel->tunnel_tls_on_data_coming) {
        tunnel->tunnel_tls_on_data_coming(tunnel, data);
    }
    buffer_release(data);
}

static void tls_async_close_cb(uv_handle_t *handle) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)handle->data;
    destroy_tls_cli_ctx(ctx);
    PRINT_INFO("outgoing connection closed.");
}

static void tls_cli_after_cb(uv_work_t *req, int status) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)req->data;
    ctx->async->data = ctx;
    uv_close((uv_handle_t*) ctx->async, tls_async_close_cb);
}

static void tls_async_send_incoming_data(struct tls_cli_ctx *ctx, const uint8_t *buf, size_t len) {
    struct tls_data_arrival *ptr = (struct tls_data_arrival *)calloc(1, sizeof(*ptr));
    ptr->ctx = ctx;
    ptr->data = buffer_create_from(buf, (size_t)len);
    ctx->async->data = (void*) ptr;
    uv_async_send(ctx->async);
}
