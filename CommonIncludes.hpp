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

#ifndef REIMUTLS_COMMONINCLUDES_HPP
#define REIMUTLS_COMMONINCLUDES_HPP

#include <string>
#include <system_error>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>

#include <unistd.h>
#include <fcntl.h>

#include <sys/un.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>



#endif //REIMUTLS_COMMONINCLUDES_HPP
