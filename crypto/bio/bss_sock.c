/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_local.h"
#include "internal/cryptlib.h"
#include "internal/ktls.h"

#include <emscripten.h>

#include <stdbool.h>
#include "../../../src/c/include/main.h"

#ifndef OPENSSL_NO_SOCK

# include <openssl/bio.h>

# ifdef WATT32
/* Watt-32 uses same names */
#  undef sock_write
#  undef sock_read
#  undef sock_puts
#  define sock_write SockWrite
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static const BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    bwrite_conv,
    sock_write,
    bread_conv,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets,         */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,                       /* sock_callback_ctrl */
};

const BIO_METHOD *BIO_s_socket(void)
{
    return &methods_sockp;
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return NULL;
    BIO_set_fd(ret, fd, close_flag);
# ifndef OPENSSL_NO_KTLS
    {
        /*
         * The new socket is created successfully regardless of ktls_enable.
         * ktls_enable doesn't change any functionality of the socket, except
         * changing the setsockopt to enable the processing of ktls_start.
         * Thus, it is not a problem to call it for non-TLS sockets.
         */
        ktls_enable(fd);
    }
# endif
    return ret;
}

static int sock_new(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return 1;
}

static int sock_free(BIO *a)
{
    if (a == NULL)
        return 0;
    if (a->shutdown) {
        if (a->init) {
            BIO_closesocket(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return 1;
}

/**
 *  ziti_readsocket
 *
 *  Provide a socket abstraction, and use async i/o, to read bytes from the Edge Router
 */

//temp
// #undef _EM_ZITI_JS
// #undef EM_ZITI_ASYNC_JS

// #define _EM_ZITI_JS(ret, c_name, js_name, params, pnames, code)                                            \
//   _EM_JS_CPP_BEGIN                                                                                 \
//   ret c_name params EM_IMPORT(js_name);                                                            \
//   EMSCRIPTEN_KEEPALIVE                                                                             \
//   __attribute__((section("em_js"), aligned(1))) char __em_js__##js_name[] =                        \
//     #params "<::>" code;                                                                           \
//   _EM_JS_CPP_END

// #define _Args(...) __VA_ARGS__
// #define STRIP_PARENS(X) X
// #define PASS_PARAMETERS(X) STRIP_PARENS( _Args (X) )
// #define ESC(...) __VA_ARGS__

// #define EM_ZITI_ASYNC_JS(ret, name, params, pnames, ...) _EM_ZITI_JS(ret, name, __asyncjs__##name, params, pnames,       \
//   "{ let arg = Object.assign({}, {ziti_readsocket_ctr, fd, out_parm, outl_parm}); return Asyncify.handleAsync(arg, async () => " #__VA_ARGS__ "); }")
//temp
// EM_ZITI_ASYNC_JS(int, ziti_readsocket, (int ziti_readsocket_ctr, int fd, char *out_parm, int outl_parm), (ziti_readsocket_ctr, fd, out_parm, outl_parm), {

//     // Get the 'socket' that maps to this fd
//     console.log('ziti_readsocket() entered fd[%d] out_parm[%o] outl_parm[%o]', fd, out_parm, outl_parm);
//     let wasmFD = _zitiContext._wasmFDsById.get( fd );
//     if (!wasmFD) { throw new Error('cannot find wasmFD'); }

//     // LOCK: OpenSSL handles are NOT thread-safe, so we must synchronize our access to it
//     // await wasmFD.socket.acquireTLSReadLock();

//     // Pull the requested number of bytes off the 'socket'
//     console.log('ziti_readsocket() fd[%d] now awaiting wasmFD.socket.fd_read()', fd);
//     let data = await wasmFD.socket.fd_read( outl_parm );
//     console.log('ziti_readsocket() fd[%d] wasmFD.socket.fd_read() returned [%o]', fd, data);

//     // UNLOCK: OpenSSL handles are NOT thread-safe, so we must synchronize our access to it
//     // wasmFD.socket.releaseTLSReadLock();

//     // Transfer the bytes into the WebAssembly heap
//     Module.HEAPU8.set(new Uint8Array(data), out_parm);

//     return data.byteLength;
// });

// start_ziti_awaitTLSDataQueue_timer(): call JS to set an async timer
// EM_JS(void, start_ziti_awaitTLSDataQueue_timer, ( int arg ), {
//   console.log("start_ziti_awaitTLSDataQueue_timer() entered: ", arg);
//   Module.ziti_awaitTLSDataQueue_timer = false;
//   setTimeout(function() {
//     Module.ziti_awaitTLSDataQueue_timer = true;
//   }, arg);
// });
// check_ziti_awaitTLSDataQueue_timer(): check if that timer occurred
// EM_JS(bool, check_ziti_awaitTLSDataQueue_timer, (), {
//   return Module.ziti_awaitTLSDataQueue_timer;
// });
// EM_JS(void, start_ziti_awaitTLSDataQueue_timer, (int ms), {
//     Asyncify.handleSleep(0, wakeUp => {
//         new Promise((resolve, reject) => {
//             setTimeout(() => {
//                 resolve();
//             }, ms);
//         })
//         .then(() => {
//             console.log('Timer expired start_ziti_awaitTLSDataQueue_timer() --->');
//                 wakeUp(1);
//         })
//     });
// })

static int ziti_readTLSDataQueue(BIO *b, char *out, int outl)
{
    char *targetCursor = out;
    int remainingTargetLen = outl;
    int targetBufferOffset = 0;
    int memcpyLenTotal = 0;
    TLSDataQueue *tlsDataQueue;
    TLSDataNODE *tlsDataNode;

    // printf("ziti_readTLSDataQueue() entered for fd[%d] out[%p] len[%d]\n", b->num, out, outl);

    // Get queue for specified FD.  The various sleep calls are done to yield/wait for 
    // initial incoming data for the FD, which will cause creation of the TLSDataQueue
    do {
        tlsDataQueue = fd_kv_getItem( b->num );
        if (NULL == tlsDataQueue) {
            // printf("ziti_readTLSDataQueue() cannot locate TLSDataQueue for fd[%d]\n", b->num);
            // printf("waiting for incoming data from wsER (1)...\n");
            emscripten_sleep(5);
        } else {
            tlsDataNode = peekTLSData(tlsDataQueue);
            if (NULL == tlsDataNode) {
                // printf("ziti_readTLSDataQueue() cannot locate TLSDataNODE for fd[%d]\n", b->num);
                // printf("waiting for incoming data from wsER (2)...\n");
                emscripten_sleep(5);
            }
        }
    }
    while ((NULL == tlsDataQueue) || (NULL == tlsDataNode));

    // Provide data from the TLSDataQueue to the caller
    do {
        // Get top data node
        tlsDataNode = peekTLSData(tlsDataQueue);
        if (NULL == tlsDataNode) {
            // printf("ziti_readTLSDataQueue() no TLSDataNODE for fd[%d]\n", b->num);
            // printf("waiting for incoming data from wsER (3)...\n");
            emscripten_sleep(5);
            continue;
        }
        if (tlsDataNode->data.offset >= tlsDataNode->data.len) {
            printf("ziti_readTLSDataQueue() ERROR: TLSDataNODE has no remaining unconsumed data fd[%d] offset[%d] len[%d]\n", b->num, tlsDataNode->data.offset, tlsDataNode->data.len);
            return( -1 );
        }

        // Calculate the shorter of either the remainingTargetLen, or the remaining unconsumed data in this tlsDataNode
        int memcpyLen = tlsDataNode->data.len - tlsDataNode->data.offset;
        // printf("ziti_readTLSDataQueue() tlsDataNode remaining unconsumed data len [%d]\n", memcpyLen);
        if (remainingTargetLen < memcpyLen) {
            // printf("ziti_readTLSDataQueue() remainingTargetLen [%d]\n", remainingTargetLen);
            memcpyLen = remainingTargetLen;
        }
        // printf("ziti_readTLSDataQueue() memcpyLen [%d]\n", memcpyLen);

        // move the data into caller's buffer
        memcpy( targetCursor, (tlsDataNode->data.buf + tlsDataNode->data.offset), memcpyLen);
        // printf("ziti_readTLSDataQueue() memcpy: [%p] [%p] [%d]\n", targetCursor, (tlsDataNode->data.buf + tlsDataNode->data.offset), memcpyLen);
        
        // adjust data cursors
        tlsDataNode->data.offset += memcpyLen;
        targetCursor += memcpyLen;
        memcpyLenTotal += memcpyLen;
        remainingTargetLen -= memcpyLen;

        // printf("ziti_readTLSDataQueue() bottom of loop: memcpyLenTotal[%d] remainingTargetLen[%d]\n", memcpyLenTotal, remainingTargetLen);
    }
    while (memcpyLenTotal < outl);

    // printf("ziti_readTLSDataQueue() exiting: [%d]\n", memcpyLenTotal);
    
    if (memcpyLenTotal != outl) {
        printf("ERROR: memcpyLenTotal[%d] !== outl[%d]", memcpyLenTotal, outl);
    }

    return( memcpyLenTotal );
}

// static void hexdump(const void *ptr, size_t len)
// {
//     const unsigned char *p = ptr;
//     size_t i, j;

//     for (i = 0; i < len; i += j) {
// 	for (j = 0; j < 16 && i + j < len; j++)
// 	    printf("%s%02x", j? "" : " ", p[i + j]);
//     }
//     printf("\n");
// }

static int sock_read(BIO *b, char *out, int outl)
{
    // static int ziti_readsocket_ctr = 0;
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
# ifndef OPENSSL_NO_KTLS
        if (BIO_get_ktls_recv(b))
            ret = ktls_read_record(b->num, out, outl);
        else
# endif
            // ret = readsocket(b->num, out, outl);
            // ret = ziti_readsocket(ziti_readsocket_ctr++, b->num, out, outl);

            ret = ziti_readTLSDataQueue(b, out, outl);
            printf("sock_read() fd[%d] ziti_readTLSDataQueue returned: [%d] outl was [%d]\n", b->num, ret, outl);
            // hexdump(out, ret);

        BIO_clear_retry_flags(b);
        if (ret <= 0) { 
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
            else if (ret == 0)
                b->flags |= BIO_FLAGS_IN_EOF;
        }
    }
    return ret;
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret = 0;

    printf("wasm.sock_write() entered: fd[%d] in[%p] len[%d]\n", b->num, in, inl);
    // hexdump(in, inl);

    clear_socket_error();
# ifndef OPENSSL_NO_KTLS
    if (BIO_should_ktls_ctrl_msg_flag(b)) {
        unsigned char record_type = (intptr_t)b->ptr;
        ret = ktls_send_ctrl_message(b->num, record_type, in, inl);
        if (ret >= 0) {
            ret = inl;
            BIO_clear_ktls_ctrl_msg_flag(b);
        }
    } else
# endif
        // the following call will eventually call js-library.js:fd_write()
        ret = writesocket(b->num, in, inl);
        printf("wasm.sock_write() writesocket() returned [%d]\n", ret);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
# ifndef OPENSSL_NO_KTLS
    ktls_crypto_info_t *crypto_info;
# endif

    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
# ifndef OPENSSL_NO_KTLS
    case BIO_CTRL_SET_KTLS:
        crypto_info = (ktls_crypto_info_t *)ptr;
        ret = ktls_start(b->num, crypto_info, num);
        if (ret)
            BIO_set_ktls_flag(b, num);
        break;
    case BIO_CTRL_GET_KTLS_SEND:
        return BIO_should_ktls_flag(b, 1) != 0;
    case BIO_CTRL_GET_KTLS_RECV:
        return BIO_should_ktls_flag(b, 0) != 0;
    case BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG:
        BIO_set_ktls_ctrl_msg_flag(b);
        b->ptr = (void *)num;
        ret = 0;
        break;
    case BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG:
        BIO_clear_ktls_ctrl_msg_flag(b);
        ret = 0;
        break;
# endif
    case BIO_CTRL_EOF:
        ret = (b->flags & BIO_FLAGS_IN_EOF) != 0;
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = sock_write(bp, str, n);
    return ret;
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

        return BIO_sock_non_fatal_error(err);
    }
    return 0;
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return 1;
    default:
        break;
    }
    return 0;
}

#endif                          /* #ifndef OPENSSL_NO_SOCK */
