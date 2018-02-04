/*
    This file is part of ReimuTLS.
    Copyright (C) 2018  ReimuNotMoe <reimuhatesfdt@gmail.com>

    ReimuTLS is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ReimuTLS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ReimuTLS.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef ReimuTLS_HPP
#define ReimuTLS_HPP

#include "CommonIncludes.hpp"


class ReimuTLS {
public:
    int FD_Target = -1;
    int FD_Pipe[2] = {-1};

    ReimuTLS() = default;
    ~ReimuTLS();

    void Init(int role=MBEDTLS_SSL_IS_CLIENT, int transport=MBEDTLS_SSL_TRANSPORT_STREAM,
	      int authmode=MBEDTLS_SSL_VERIFY_REQUIRED);

    void InitSSLContext();
    void DestroySSLContext();
    void InitSSLConfig();
    void DestroySSLConfig();
    void InitCookieContext();
    void DestroyCookieContext();
    void InitEntropyContext();
    void DestroyEntropyContext();
    void InitCertList();
    void DestroyCertList();
    void InitPrivateKey();
    void DestroyPrivateKey();
    void InitCtrDrbg();
    void DestroyCtrDrbg();
    void InitTimerContext();
    void DestroyTimerContext();

    void SetIOTarget_FD(int fd);

    int ParseCertData(const unsigned char *cert_data, size_t len);
    int ParseCertFile(const char *path_file);
    int ParseCertDir(const char *path_dir);
    int ParsePrivateKeyData(const unsigned char *key, size_t keylen, const unsigned char *pwd=NULL, size_t pwdlen=0);

    int SSLConfigDefaults(int endpoint, int transport, int preset);
    void SSLConfigAuthMode(int __auth_mode);
    void SSLConfigRng(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    void SSLConfigRng();
    void SSLSetBIO(void *p_bio, int (*f_send)(void *, const unsigned char *, size_t),
		   int (*f_recv)(void *, unsigned char *, size_t),
		   int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t));
    void SSLSetBIO(int (*f_send)(void *, const unsigned char *, size_t),
		   int (*f_recv)(void *, unsigned char *, size_t),
		   int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t));
    void SSLSetBIO();
    void SSLConfigCAChain(mbedtls_x509_crt *ca_chain, mbedtls_x509_crl *ca_crl);
    void SSLConfigCAChain();
    int SSLConfOwnCert(mbedtls_x509_crt *own_cert, mbedtls_pk_context *pk_key);
    int SSLConfOwnCert();
    void SSLConfDTLSCookies(mbedtls_ssl_cookie_write_t *f_cookie_write, mbedtls_ssl_cookie_check_t *f_cookie_check,
			   void *p_cookie);
    void SSLConfDTLSCookies();
    void SSLConfDbg(void(*f_dbg)(void *, int, const char *, int, const char *), void *p_dbg);
    void SSLConfDbg();
    int SSLCookieSetup(int(*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    int SSLCookieSetup();
    int SSLSetup();
    int SSLSetHostName(const char *hostname);
    void SSLSetTimerCb(void *p_timer, void (*f_set_timer)(void *, uint32_t int_ms, uint32_t fin_ms),
		       int (*f_get_timer)(void *));
    void SSLSetTimerCb();
    int SSLSetClientTransportID(const unsigned char *info, size_t ilen);
    int SSLHandShake();
    int SSLGetVerifyResult();
    int CtrDrbgSeed(int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy, const unsigned char *custom,
		    size_t len);
    int CtrDrbgSeed();

    int SSLRead(unsigned char *buf, size_t len);
    int SSLWrite(const unsigned char *buf, size_t len);

    int CreatePipe();

private:

    bool Inited = 0;

    mbedtls_ssl_cookie_ctx *CookieContext = NULL;
    mbedtls_entropy_context *EntropyContext = NULL;
    mbedtls_ctr_drbg_context *ctr_drbg = NULL;
    mbedtls_ssl_context *SSLContext = NULL;
    mbedtls_ssl_config *SSLConfig = NULL;
    mbedtls_x509_crt *CertList = NULL;
    mbedtls_pk_context *PrivateKey = NULL;
    mbedtls_timing_delay_context *TimerContext = NULL;

    static void *builtin_pipe_thread(void *userp);
    static int builtin_callback_fd_read(void *userp, unsigned char *buf, size_t len);
    static int builtin_callback_fd_read_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);
    static int builtin_callback_fd_write(void *userp, const unsigned char *buf, size_t len);
    static int builtin_callback_fd_would_block(ReimuTLS *ctx);

    static void my_debug(void *ctx, int level, const char *file, int line, const char *str);

};

#endif // ReimuTLS_HPP