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

#include <sys/time.h>
#include "ReimuTLS.hpp"

void ReimuTLS::IOSetTargetFD(int fd) {
	FD_Target = fd;
	SSLSetBIO();
}

int ReimuTLS::timed_read(int fd, void *buf, size_t len, unsigned int usecs) { // ms * 1000
	fd_set fds;
	struct timeval tv;
	int rc_select;
	ssize_t rc_read;
	size_t read_total;

begin:
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	tv.tv_sec = 0;
	read_total = 0;

	while (1) {
		tv.tv_usec = usecs;
		rc_select = select(fd + 1, &fds, NULL, NULL, &tv);

		/* Zero fds ready means we timed out */
		if (rc_select == 0) {
			if (read_total)
				goto ret;
		} else if (rc_select == 1) {
			rc_read = read(fd, buf+read_total, len-read_total);
//			fprintf(stderr, "read: %zd\n", rc_read);
			if (rc_read > 0) {
				read_total += rc_read;
				if (read_total == len)
					goto ret;
			} else if (rc_read == 0) {
				goto ret;
			} else {
				return -1;
			}
		} else {
			return -1;
		}

	}


ret:
	fprintf(stderr, "read_total: %zu/%zu\n", read_total, len);
	return (int)(read_total);
}

ssize_t ReimuTLS::timed_read_wrapper(int fd, void *buf, size_t len) {
	return timed_read(fd, buf, len, 2 * 1000);
}

int ReimuTLS::builtin_callback_fd_read(void *userp, unsigned char *buf, size_t len) {
	int ret;
	auto ctx = (ReimuTLS *)userp;
	int fd = ctx->FD_Target;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	if (ctx->IODelay)
		ret = timed_read(fd, buf, len, ctx->IODelay);
	else
		ret = (int)read(fd, buf, len);

	fprintf(stderr, "fd_read: %d\n", ret);

	if (ret < 0) {
		if (builtin_callback_fd_would_block((ReimuTLS *)userp) != 0)
			return MBEDTLS_ERR_SSL_WANT_READ;

		if (errno == EPIPE || errno == ECONNRESET)
			return MBEDTLS_ERR_NET_CONN_RESET;

		if (errno == EINTR)
			return MBEDTLS_ERR_SSL_WANT_READ;

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return ret;
}

int ReimuTLS::builtin_callback_fd_read_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
	int ret;
	struct timeval tv;
	fd_set read_fds;
	int fd = ((ReimuTLS *)ctx)->FD_Target;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	tv.tv_sec  = timeout / 1000;
	tv.tv_usec = (timeout % 1000)  * 1000;

	ret = select(fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv);

	/* Zero fds ready means we timed out */
	if (ret == 0)
		return MBEDTLS_ERR_SSL_TIMEOUT;

	if (ret < 0) {
		if (errno == EINTR)
			return MBEDTLS_ERR_SSL_WANT_READ;

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	/* This call will not block */
	return builtin_callback_fd_read(ctx, buf, len);
}

int ReimuTLS::builtin_callback_fd_write(void *userp, const unsigned char *buf, size_t len) {
	int rc_write, rc_write_cksum;
	auto ctx = (ReimuTLS *)userp;
	int fd = ctx->FD_Target;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

//	auto cksum = crc16(buf, len);
//
//	timeval ts_write_start;
//	gettimeofday(&ts_write_start, NULL);

	rc_write = (int)write(fd, buf, len);
//	rc_write_cksum = (int)write(fd, &cksum, 2);

//	timeval ts_write_end;
//	gettimeofday(&ts_write_end, NULL);
//
//	timeval ts_write_diff;
//	timersub(&ts_write_start, &ts_write_end, &ts_write_diff);

	fprintf(stderr, "fd_write: %d (%d)\n", rc_write, rc_write_cksum);

//	auto sleeptime = ctx->IODelay + (ctx->IOSpeed*(len+2)-(ts_write_diff.tv_usec+ts_write_diff.tv_sec*1000000));
//	fprintf(stderr, "sleeping %ld usecs\n", sleeptime);

	if (ctx->IODelay)
		usleep(409600);


	if (rc_write < 0) {
		if (builtin_callback_fd_would_block((ReimuTLS *)userp) != 0)
			return MBEDTLS_ERR_SSL_WANT_WRITE;


		if (errno == EPIPE || errno == ECONNRESET)
			return MBEDTLS_ERR_NET_CONN_RESET;

		if (errno == EINTR)
			return MBEDTLS_ERR_SSL_WANT_WRITE;

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return rc_write;
}

int ReimuTLS::builtin_callback_fd_would_block(ReimuTLS *ctx) {
	int err = errno;

	/*
	 * Never return 'WOULD BLOCK' on a non-blocking socket
	 */
	if ((fcntl(ctx->FD_Target, F_GETFL)  & O_NONBLOCK)  != O_NONBLOCK) {
		errno = err;
		return 0;
	}

	switch (errno = err) {
#if defined EAGAIN
		case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
			return 1;
	}
	return 0;
}