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

#include <cassert>
#include "../../ReimuTLS.hpp"

const uint64_t owo = 0;

int main(int argc, char **argv){
	if (argc < 2) {
		return 2;
	}

	int fd = open(argv[1], O_RDWR);

	assert(fd > 0);
//	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	ReimuTLS rt;


	rt.Init(MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_VERIFY_OPTIONAL);
	rt.SSLConfDbg();
	rt.IOSetTargetFD(fd);
	assert(rt.ParseCertData((const unsigned char *)mbedtls_test_srv_crt, mbedtls_test_srv_crt_len) == 0);
	assert(rt.ParseCertData((const unsigned char *)mbedtls_test_cas_pem, mbedtls_test_cas_pem_len) == 0);
	assert(rt.ParsePrivateKeyData((const unsigned char *)mbedtls_test_srv_key, mbedtls_test_srv_key_len) == 0);
	rt.SSLConfigCAChain();
	assert(rt.SSLConfOwnCert() == 0);
	assert(rt.SSLCookieSetup() == 0);
	rt.SSLConfDTLSCookies(NULL, NULL, NULL);
	assert(rt.SSLSetup() == 0);
//	rt.SSLSetTimerCb();
	assert(rt.SSLSetClientTransportID((const u_char *)&owo, 8) == 0);

	int ret;
	fprintf(stderr, "Start handshake on %s\n", argv[1]);

//	rt.IODelay = 2 * 1000;
//	rt.IOSetReadFunc(1);

//	rt.SetIODelayByLinkSpeed(9600);
//	rt.SSLConfHandshakeTimeout(10*1000, 80*1000);

	do {
		ret = rt.SSLHandShake();
		fprintf(stderr, "SSLHandShake() returned %d\n", ret);
	} while ( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE );

	sleep(1);

//	rt.IOSetReadFunc(0);

	char buf[512];

	while (int rc_read = read(STDIN_FILENO, buf, 64)) {
		ret = rt.SSLWrite((const unsigned char *) buf, rc_read);
		fprintf(stderr, "SSLWrite() returned %d\n", ret);
//		usleep(200*1000);
	}



}