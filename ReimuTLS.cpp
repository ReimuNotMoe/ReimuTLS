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


void ReimuTLS::Init(int role, int transport, int authmode) {
	InitSSLContext();
	InitSSLConfig();
	InitCertList();
	InitCtrDrbg();
	InitEntropyContext();

	int ret;
	if ((ret = CtrDrbgSeed()) != 0)  {
		throw std::system_error(ret, std::generic_category(), "mbedtls_ctr_drbg_seed");
	}

	if ((ret = SSLConfigDefaults(role, transport, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)  {
		throw std::system_error(ret, std::generic_category(), "mbedtls_ssl_config_defaults");
	}

	SSLConfigAuthMode(authmode);
	SSLConfigRng();

	InitCookieContext();

	if (transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		InitTimerContext();
	}

	if (role == MBEDTLS_SSL_IS_SERVER) {
		InitPrivateKey();
	}

	Inited = 1;
}

void ReimuTLS::InitSSLContext() {
	DestroySSLContext();
	SSLContext = new mbedtls_ssl_context;
	mbedtls_ssl_init(SSLContext);
}

void ReimuTLS::DestroySSLContext() {
	if (SSLContext) {
		mbedtls_ssl_free(SSLContext);
		delete SSLContext;
		SSLContext = NULL;
	}
}

void ReimuTLS::InitCookieContext() {
	DestroyCookieContext();
	CookieContext = new mbedtls_ssl_cookie_ctx;
	mbedtls_ssl_cookie_init(CookieContext);
}

void ReimuTLS::DestroyCookieContext() {
	if (CookieContext) {
		mbedtls_ssl_cookie_free(CookieContext);
		delete CookieContext;
		CookieContext = NULL;
	}
}

void ReimuTLS::InitSSLConfig() {
	DestroySSLConfig();
	SSLConfig = new mbedtls_ssl_config;
	mbedtls_ssl_config_init(SSLConfig);
}

void ReimuTLS::DestroySSLConfig() {
	if (SSLConfig) {
		mbedtls_ssl_config_free(SSLConfig);
		delete SSLConfig;
		SSLConfig = NULL;
	}
}

void ReimuTLS::InitEntropyContext() {
	DestroyEntropyContext();
	EntropyContext = new mbedtls_entropy_context;
	mbedtls_entropy_init(EntropyContext);
}

void ReimuTLS::DestroyEntropyContext() {
	if (EntropyContext) {
		mbedtls_entropy_free(EntropyContext);
		delete EntropyContext;
		EntropyContext = NULL;
	}
}

void ReimuTLS::InitCertList() {
	DestroyCertList();
	CertList = new mbedtls_x509_crt;
	mbedtls_x509_crt_init(CertList);
}

void ReimuTLS::DestroyCertList() {
	if (CertList) {
		mbedtls_x509_crt_free(CertList);
		delete CertList;
		CertList = NULL;
	}
}

void ReimuTLS::InitPrivateKey() {
	DestroyPrivateKey();
	PrivateKey = new mbedtls_pk_context;
	mbedtls_pk_init(PrivateKey);
}

void ReimuTLS::DestroyPrivateKey() {
	if (PrivateKey) {
		mbedtls_pk_free(PrivateKey);
		delete PrivateKey;
		PrivateKey = NULL;
	}
}

void ReimuTLS::InitCtrDrbg() {
	DestroyCtrDrbg();
	ctr_drbg = new mbedtls_ctr_drbg_context;
	mbedtls_ctr_drbg_init(ctr_drbg);
}

void ReimuTLS::DestroyCtrDrbg() {
	if (ctr_drbg) {
		mbedtls_ctr_drbg_free(ctr_drbg);
		delete ctr_drbg;
		ctr_drbg = NULL;
	}
}

void ReimuTLS::InitTimerContext() {
	DestroyTimerContext();
	TimerContext = new mbedtls_timing_delay_context;
}

void ReimuTLS::DestroyTimerContext() {
	if (TimerContext) {
		delete TimerContext;
		TimerContext = NULL;
	}
}

ReimuTLS::~ReimuTLS() {
	DestroyCertList();
	DestroyCookieContext();
	DestroyCtrDrbg();
	DestroyEntropyContext();
	DestroyPrivateKey();
	DestroySSLConfig();
	DestroySSLContext();
	DestroyTimerContext();
}

int ReimuTLS::SetIODelayByLinkSpeed(int bps, int guard_interval) {
	IODelay = 1200;
	printf("IODelay: %d\n", IODelay);
	return IODelay;
}

uint16_t ReimuTLS::crc16(const uint8_t *data, uint16_t size) {
	const uint16_t CRC16 = 0x8005;

	uint16_t out = 0;
	int bits_read = 0, bit_flag;

	/* Sanity check: */
	if(data == NULL)
		return 0;

	while (size > 0) {
		bit_flag = out >> 15;

		/* Get next bit: */
		out <<= 1;
		out |= (*data >> bits_read) & 1; // item a) work from the least significant bits

		/* Increment bit counter: */
		bits_read++;
		if(bits_read > 7) {
			bits_read = 0;
			data++;
			size--;
		}

		/* Cycle check: */
		if (bit_flag)
			out ^= CRC16;

	}

	// item b) "push out" the last 16 bits
	int i;
	for (i = 0; i < 16; ++i) {
		bit_flag = out >> 15;
		out <<= 1;
		if (bit_flag)
			out ^= CRC16;
	}

	// item c) reverse the bits
	uint16_t crc = 0;
	i = 0x8000;
	int j = 0x0001;
	for (; i != 0; i >>=1, j <<= 1) {
		if (i & out) crc |= j;
	}

	return crc;
}

bool ReimuTLS::crc16_verify(const uint8_t *data, uint16_t size) {
	if (size < 3)
		return false;

	uint16_t crc16_this = crc16(data, size-2);
	uint16_t crc16_good;
	memcpy(&crc16_good, data+size-2, 2);

	return crc16_this == crc16_good;
}


