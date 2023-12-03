/*
 * TLS/SSL Protocol
 * Copyright (c) 2011 Martin Storsjo
 * Copyright (c) 2018 samsamsam@o2.pl
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#include "tls.h"
#include "libavcodec/internal.h"
#include "libavutil/avstring.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"

#undef HAVE_SYS_TIME_H
#define NO_FILESYSTEM
#include <wolfssl/ssl.h>

typedef struct TLSContext {
    const AVClass *class;
    TLSShared tls_shared;
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
} TLSContext;

static int wolfssl_init;

void ff_wolfssl_init(void)
{
    avpriv_lock_avformat();
    if (!wolfssl_init) {
        wolfSSL_Init();
    }
    wolfssl_init++;
    avpriv_unlock_avformat();
}

void ff_wolfssl_deinit(void)
{
    avpriv_lock_avformat();
    wolfssl_init--;
    if (!wolfssl_init) {
        wolfSSL_Cleanup();
    }
    avpriv_unlock_avformat();
}

static int print_tls_error(URLContext *h, int ret)
{
    char error_buffer[WOLFSSL_MAX_ERROR_SZ];
    av_log(h, AV_LOG_ERROR, "%ld -> %s\n", wolfSSL_ERR_get_error(), wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
    return AVERROR(EIO);
}

static int tls_close(URLContext *h)
{
    TLSContext *c = h->priv_data;
    if (c->ssl) {
        wolfSSL_shutdown(c->ssl);
        wolfSSL_free(c->ssl);
    }
    if (c->ctx)
        wolfSSL_CTX_free(c->ctx);
    if (c->tls_shared.tcp)
        ffurl_close(c->tls_shared.tcp);
    //ff_wolfssl_deinit();
    return 0;
}

static ssize_t wolfssl_recv_callback(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    URLContext *h = (URLContext*) ctx;
    int ret = ffurl_read(h, buf, sz);
    if (ret >= 0)
        return ret;
    if (ret == AVERROR_EXIT)
        return WOLFSSL_CBIO_ERR_GENERAL;
    errno = EIO;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static ssize_t wolfssl_send_callback(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    URLContext *h = (URLContext*) ctx;
    int ret = ffurl_write(h, buf, sz);
    if (ret >= 0)
        return ret;
    if (ret == AVERROR_EXIT)
        return WOLFSSL_CBIO_ERR_GENERAL;
    errno = EIO;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int tls_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    char error_buffer[WOLFSSL_MAX_ERROR_SZ];
    TLSContext *p = h->priv_data;
    TLSShared *c = &p->tls_shared;
    int ret;

    //ff_wolfssl_init();

    if ((ret = ff_tls_open_underlying(c, h, uri, options)) < 0)
        goto fail;

     p->ctx = wolfSSL_CTX_new(c->listen ? wolfSSLv23_server_method() : wolfSSLv23_client_method()); // wolfTLSv1_1_client_method
#ifndef NO_FILESYSTEM
    if (!p->ctx) {
        av_log(h, AV_LOG_ERROR, "%s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
        ret = AVERROR(EIO);
        goto fail;
    }
    if (c->ca_file) {
        if (!wolfSSL_CTX_load_verify_locations(p->ctx, c->ca_file, NULL))
            av_log(h, AV_LOG_ERROR, "wolfSSL_CTX_load_verify_locations %s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
    }
    if (c->cert_file && !wolfSSL_CTX_use_certificate_chain_file(p->ctx, c->cert_file)) {
        av_log(h, AV_LOG_ERROR, "Unable to load cert file %s: %s\n",
               c->cert_file, wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
        ret = AVERROR(EIO);
        goto fail;
    }
    if (c->key_file && !wolfSSL_CTX_use_PrivateKey_file(p->ctx, c->key_file, WOLFSSL_FILETYPE_PEM)) {
        av_log(h, AV_LOG_ERROR, "Unable to load key file %s: %s\n",
               c->key_file, wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
        ret = AVERROR(EIO);
        goto fail;
    }
#endif
    
    wolfSSL_CTX_set_verify(p->ctx,
                           c->verify ? WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT : 
                                       WOLFSSL_VERIFY_NONE,
                           NULL);
    
#ifdef HAVE_SNI
    if (!c->listen && !c->numerichost && !wolfSSL_CTX_UseSNI(p->ctx, WOLFSSL_SNI_HOST_NAME, c->host,
                          (unsigned short)strlen(c->host))) {
        av_log(h, AV_LOG_ERROR, "failed to configure server name indication (SNI) %s: %ld -> %s\n",
                c->host, wolfSSL_ERR_get_error(), wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
    }
#endif

    wolfSSL_CTX_SetIORecv(p->ctx, wolfssl_recv_callback);
    wolfSSL_CTX_SetIOSend(p->ctx, wolfssl_send_callback);
    
    p->ssl = wolfSSL_new(p->ctx);
    if (!p->ssl) {
        av_log(h, AV_LOG_ERROR, "%s\n", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), error_buffer));
        ret = AVERROR(EIO);
        goto fail;
    }
    
    wolfSSL_SetIOReadCtx(p->ssl, c->tcp);
    wolfSSL_SetIOWriteCtx(p->ssl, c->tcp); 
    
    ret = c->listen ? wolfSSL_accept(p->ssl) : wolfSSL_connect(p->ssl);
    if (ret == 0) {
        av_log(h, AV_LOG_ERROR, "Unable to negotiate TLS/SSL session\n");
        ret = AVERROR(EIO);
        goto fail;
    } else if (ret < 0) {
        ret = print_tls_error(h, ret);
        goto fail;
    }
    
    return 0;
fail:
    tls_close(h);
    return ret;
}

static int tls_read(URLContext *h, uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    int ret = wolfSSL_read(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return print_tls_error(h, ret);
}

static int tls_write(URLContext *h, const uint8_t *buf, int size)
{
    TLSContext *c = h->priv_data;
    int ret = wolfSSL_write(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return print_tls_error(h, ret);
}

static int tls_get_file_handle(URLContext *h)
{
    TLSContext *c = h->priv_data;
    return ffurl_get_file_handle(c->tls_shared.tcp);
}

static const AVOption options[] = {
    TLS_COMMON_OPTIONS(TLSContext, tls_shared),
    { NULL }
};

static const AVClass tls_class = {
    .class_name = "tls",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_tls_protocol = {
    .name           = "tls",
    .url_open2      = tls_open,
    .url_read       = tls_read,
    .url_write      = tls_write,
    .url_close      = tls_close,
    .url_get_file_handle = tls_get_file_handle,
    .priv_data_size = sizeof(TLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &tls_class,
};
