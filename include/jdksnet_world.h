#pragma once
/*
Copyright (c) 2014, J.D. Koftinoff Software, Ltd.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if defined( __linux__ )
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <errno.h>
#include <strings.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#elif defined( __APPLE__ )
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <errno.h>
#include <strings.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <net/if_dl.h>
#include <pcap.h>
#elif defined( _WIN32 )
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <Windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include "jdksavdecc_ms.h"
#include <pcap.h>
#pragma comment( lib, "IPHLPAPI.lib" )
#pragma comment( lib, "wpcap.lib" )
#pragma comment( lib, "Ws2_32.lib" )
static inline void bzero( void *buf, size_t sz )
{
    memset( buf, 0, sz );
}
#endif

#include "jdksavdecc.h"
#include "jdksavdecc_util.h"
#include "jdksavdecc_frame.h"

#ifndef JDKSNET_ERROR_STDERR
#define JDKSNET_ERROR_STDERR 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef JDKSNET_ERROR_PROC
extern void JDKSNET_ERROR_PROC( fmt, ... );
#define jdksnet_error( ... ) JDKSNET_ERROR_PROC( __VA_ARGS__ )
#else
#if JDKSNET_ERROR_STDERR == 1
#define jdksnet_error( ... ) fprintf( stderr, __VA_ARGS__ )
#else
#define jdksnet_error( ... )
#endif
#endif

bool jdksnet_init( void );

int jdksnet_gettimeofday( struct timeval *tv );

static inline uint64_t jdksnet_time_in_microseconds( void )
{
    uint64_t cur_time;
    struct timeval tv;
    jdksnet_gettimeofday( &tv );
    cur_time = ( (uint64_t)tv.tv_sec * 1000000 ) + ( tv.tv_usec );
    return cur_time;
}

#ifdef __cplusplus
}
#endif
