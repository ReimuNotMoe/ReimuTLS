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

#include "ReimuTLS.hpp"

int ReimuTLS::SSLRead(unsigned char *buf, size_t len) {
	return mbedtls_ssl_read(SSLContext, buf, len);
}

int ReimuTLS::SSLWrite(const unsigned char *buf, size_t len) {
	return mbedtls_ssl_write(SSLContext, buf, len);
}

int ReimuTLS::ParseCertData(const unsigned char *cert_data, size_t len) {
	return mbedtls_x509_crt_parse(CertList, cert_data, len);
}

int ReimuTLS::ParseCertFile(const char *path_file) {
	return mbedtls_x509_crt_parse_file(CertList, path_file);
}

int ReimuTLS::ParseCertDir(const char *path_dir) {
	return mbedtls_x509_crt_parse_path(CertList, path_dir);
}

int ReimuTLS::ParsePrivateKeyData(const unsigned char *key, size_t keylen, const unsigned char *pwd, size_t pwdlen) {
	return mbedtls_pk_parse_key(PrivateKey, key, keylen, pwd, pwdlen);
}

void ReimuTLS::SSLConfigAuthMode(int __auth_mode) {
	mbedtls_ssl_conf_authmode(SSLConfig, __auth_mode);
}

void ReimuTLS::SSLConfigCAChain(mbedtls_x509_crt *ca_chain, mbedtls_x509_crl *ca_crl) {
	mbedtls_ssl_conf_ca_chain(SSLConfig, ca_chain, ca_crl);
}

void ReimuTLS::SSLConfigCAChain() {
	SSLConfigCAChain(CertList, NULL);
}

void ReimuTLS::SSLSetBIO(void *p_bio, int (*f_send)(void *, const unsigned char *, size_t),
			 int (*f_recv)(void *, unsigned char *, size_t),
			 int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t)) {
	mbedtls_ssl_set_bio(SSLContext, p_bio, f_send, f_recv, f_recv_timeout);
}

void ReimuTLS::SSLSetBIO(int (*f_send)(void *, const unsigned char *, size_t),
			 int (*f_recv)(void *, unsigned char *, size_t),
			 int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t)) {
	SSLSetBIO(this, f_send, f_recv, f_recv_timeout);
}

void ReimuTLS::SSLSetBIO() {
	SSLSetBIO(&builtin_callback_fd_write, NULL, &builtin_callback_fd_read_timeout);
}

void ReimuTLS::SSLConfigRng(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	mbedtls_ssl_conf_rng(SSLConfig, f_rng, p_rng);
}

void ReimuTLS::SSLConfigRng() {
	SSLConfigRng(mbedtls_ctr_drbg_random, ctr_drbg);
}

int ReimuTLS::SSLSetHostName(const char *hostname) {
	return mbedtls_ssl_set_hostname(SSLContext, hostname);
}

int ReimuTLS::SSLSetClientTransportID(const unsigned char *info, size_t ilen) {
	return mbedtls_ssl_set_client_transport_id(SSLContext, info, ilen);
}

int ReimuTLS::SSLSetup() {
	return mbedtls_ssl_setup(SSLContext, SSLConfig);
}

int ReimuTLS::SSLHandShake() {
	return mbedtls_ssl_handshake(SSLContext);
}

int ReimuTLS::SSLGetVerifyResult() {
	return mbedtls_ssl_get_verify_result(SSLContext);
}

int ReimuTLS::SSLConfOwnCert(mbedtls_x509_crt *own_cert, mbedtls_pk_context *pk_key) {
	return mbedtls_ssl_conf_own_cert(SSLConfig, own_cert, pk_key);
}

int ReimuTLS::SSLConfOwnCert() {
	return SSLConfOwnCert(CertList, PrivateKey);
}

int ReimuTLS::SSLConfigDefaults(int endpoint, int transport, int preset) {
	return mbedtls_ssl_config_defaults(SSLConfig, endpoint, transport, preset);
}

int
ReimuTLS::CtrDrbgSeed(int (*f_entropy)(void *, unsigned char *, size_t), void *p_entropy, const unsigned char *custom,
		      size_t len) {
	return mbedtls_ctr_drbg_seed(ctr_drbg, f_entropy, p_entropy, custom, len);
}

int ReimuTLS::CtrDrbgSeed() {
	return CtrDrbgSeed(mbedtls_entropy_func, EntropyContext, NULL, 0);
}

int ReimuTLS::SSLCookieSetup(int (*f_rng)(void *, unsigned char *, size_t), void *p_rng) {
	return mbedtls_ssl_cookie_setup(CookieContext, f_rng, p_rng);
}

int ReimuTLS::SSLCookieSetup() {
	return SSLCookieSetup(mbedtls_ctr_drbg_random, ctr_drbg);
}

void
ReimuTLS::SSLConfDTLSCookies(mbedtls_ssl_cookie_write_t *f_cookie_write, mbedtls_ssl_cookie_check_t *f_cookie_check,
			     void *p_cookie) {
	mbedtls_ssl_conf_dtls_cookies(SSLConfig, f_cookie_write, f_cookie_check, p_cookie);
}

void ReimuTLS::SSLConfDTLSCookies() {
	SSLConfDTLSCookies(mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, CookieContext);
}

void
ReimuTLS::SSLSetTimerCb(void *p_timer, void (*f_set_timer)(void *, uint32_t, uint32_t), int (*f_get_timer)(void *)) {
	mbedtls_ssl_set_timer_cb(SSLContext, p_timer, f_set_timer, f_get_timer);
}

void ReimuTLS::SSLSetTimerCb() {
	SSLSetTimerCb(TimerContext, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
}

void ReimuTLS::SSLConfDbg(void (*f_dbg)(void *, int, const char *, int, const char *), void *p_dbg) {
	mbedtls_ssl_conf_dbg(SSLConfig, f_dbg, p_dbg);
}

void ReimuTLS::SSLConfDbg() {
	SSLConfDbg(my_debug, stdout);
}

void ReimuTLS::my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	((void) level);
	fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}



