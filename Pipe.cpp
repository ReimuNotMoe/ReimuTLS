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

int ReimuTLS::CreatePipe() {
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, FD_Pipe);

	if (ret != 0) {
		throw std::system_error(errno, std::generic_category(), "socketpair");
	}

	fcntl(FD_Pipe[1], F_SETFL, fcntl(FD_Pipe[1], F_GETFL, 0) | O_NONBLOCK);
	return FD_Pipe[0];
}

void *ReimuTLS::builtin_pipe_thread(void *userp) {
	auto ctx = (ReimuTLS *)userp;

	struct pollfd fds[1];
	int ret;

	uint8_t rbuf[4096], wbuf[4096];
	ssize_t rc_read = -1, rc_write = -1, rc_ssl_read = -1, rc_ssl_write = -1;
	size_t pos_write = 0;

	fds[0].fd = ctx->FD_Pipe[1];
	fds[0].events = POLLIN | POLLOUT;

	while (poll(fds, 1, -1) >= 0) {
		if (fds->revents & POLLIN) {
			rc_read = read(fds[0].fd, rbuf, 4096);
			if (rc_read > 0) {
				rc_ssl_write = ctx->SSLWrite(rbuf, (size_t)rc_read);
				if (rc_ssl_write < 1) {
					ret = 3;
					goto exit;
				}
			} else {
				pthread_exit((void *)2);
			}
		} else if (fds->revents & POLLOUT) {
			if (!pos_write) {
				rc_ssl_read = ctx->SSLRead(wbuf, 4096);
				if (rc_read < 1) {
					ret = 3;
					goto exit;
				}
			}
			rc_write = write(fds[0].fd, wbuf+pos_write, 4096-pos_write);

			if (rc_write < 1) {
				ret = 3;
				goto exit;
			}

			if (rc_write < rc_ssl_read-pos_write)
				pos_write += (size_t)rc_write;

		}
	}

exit:
	pthread_exit((void *)(intptr_t)ret);
}

