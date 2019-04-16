#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include "cmd_line_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GET_REQUEST "GET %s HTTP/1.0\r\nExtra-header: "
#define GET_REQUEST_END "\r\n\r\n"

#define ALPN_LIST_SIZE  10
#define DFL_PSK_IDENTITY "Client_identity"
#define MAX_REQUEST_SIZE      20000
#define MAX_REQUEST_SIZE_STR "20000"
#define DFL_REQUEST_SIZE        -1
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM

static void my_debug(void *ctx, int level, const char *file, int line, const char *str);

int main(int argc, char *argv[]) {
    struct cmd_line_info *cmd_line;
    int ret = 0, len, tail_len, written, frags, retry_left, proto;
    mbedtls_net_context connect_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    char *alpn_list[ALPN_LIST_SIZE] = { NULL };
    const char *pers = app_name(argv[0]);
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
    int transport = DFL_TRANSPORT;
    int exchanges = 1;

    cmd_line = cmd_line_info_create(argc, argv);
    if (cmd_line->help_flag) {
        return usage(argc, argv);
    }

    mbedtls_net_init( &connect_ctx );
    mbedtls_ssl_init( &ssl_ctx );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &clicert );
    mbedtls_pk_init( &pkey );

    mbedtls_debug_set_threshold( cmd_line->dump_level );

    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
        &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }
    if (cmd_line->root_cert_file) {
        ret = mbedtls_x509_crt_parse_file(&cacert, cmd_line->root_cert_file);
    }

    ret = mbedtls_x509_crt_parse( &clicert,
        (const unsigned char *) mbedtls_test_cli_crt,
        mbedtls_test_cli_crt_len );

    ret = mbedtls_pk_parse_key(&pkey,
        (const unsigned char *)mbedtls_test_cli_key,
        mbedtls_test_cli_key_len, NULL, 0 );


    mbedtls_printf("  . Connecting to %s/%s/%s...",
        transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "tcp" : "udp",
        cmd_line->server_addr, cmd_line->server_port);
    fflush( stdout );

    proto = (transport == MBEDTLS_SSL_TRANSPORT_STREAM) ? MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP;
    ret = mbedtls_net_connect(&connect_ctx, cmd_line->server_addr, cmd_line->server_port, proto);
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
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

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

    if (cmd_line->root_cert_file) {
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    }

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if ((ret = mbedtls_ssl_set_hostname(&ssl_ctx, cmd_line->server_addr)) != 0) {
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

    /* 6. Write the GET request */
    retry_left = 0;
send_request:
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );

    len = mbedtls_snprintf((char *)buf, sizeof(buf)-1, GET_REQUEST, cmd_line->request_page);
    tail_len = (int) strlen(GET_REQUEST_END);

    /* Add padding to GET request to reach request_size in length */
    if ((request_size != DFL_REQUEST_SIZE) && ((len + tail_len) < request_size)) {
        memset(buf + len, 'A', request_size - len - tail_len);
        len += request_size - len - tail_len;
    }

    strncpy((char *)buf + len, GET_REQUEST_END, sizeof(buf) - len - 1);
    len += tail_len;

    /* Truncate if request size is smaller than the "natural" size */
    if ((request_size != DFL_REQUEST_SIZE) && (len > request_size)) {
        len = request_size;

        /* Still end with \r\n unless that's really not possible */
        if( len >= 2 ) buf[len - 2] = '\r';
        if( len >= 1 ) buf[len - 1] = '\n';
    }

    if (transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
        written = 0;
        frags = 0;

        do {
            while ((ret = mbedtls_ssl_write(&ssl_ctx, buf + written, len - written)) < 0) {
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
    }
    else {
        /* Not stream, so datagram, omitted for us */
    }

    buf[written] = '\0';
    mbedtls_printf(" %d bytes written in %d fragments\n\n%s\n", written, frags, (char *)buf);

    /* Send a non-empty request if request_size == 0 */
    if (len == 0) {
        request_size = DFL_REQUEST_SIZE;
        goto send_request;
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
            mbedtls_printf(" %d bytes read\n\n%s", len, (char *)buf);

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

    /* 7c. Continue doing data exchanges? */
    if (--exchanges > 0) {
        goto send_request;
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
    return ret;
}

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: |%d| %s", basename, line, level, str);
    fflush((FILE *)ctx);
}
