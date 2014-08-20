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

#include "jdksnet_world.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined( __linux__ )

struct jdksnet_rawsock
{
    int m_fd;
    uint16_t m_ethertype;
    uint8_t m_my_mac[6];
    uint8_t m_default_dest_mac[6];
    int m_interface_id;
    void *m_additional;
};

#elif defined( __APPLE__ )

#define AF_PACKET AF_LINK

struct jdksnet_rawsock
{
    int m_fd;
    uint16_t m_ethertype;
    uint8_t m_my_mac[6];
    uint8_t m_default_dest_mac[6];
    int m_interface_id;
    void *m_additional;
    void *m_pcap;
};

#elif defined( _WIN32 )

struct jdksnet_rawsock
{
    SOCKET m_fd;
    uint16_t m_ethertype;
    uint8_t m_my_mac[6];
    uint8_t m_default_dest_mac[6];
    int m_interface_id;
    void *m_additional;
    void *m_pcap;
};
#endif

int jdksnet_rawsock_open( struct jdksnet_rawsock *self,
                          uint16_t ethertype,
                          const char *interface_name,
                          const struct jdksavdecc_eui48 *join_multicast );

void jdksnet_rawsock_close( struct jdksnet_rawsock *self );

ssize_t jdksnet_rawsock_send( struct jdksnet_rawsock *self, const struct jdksavdecc_frame *frame );

ssize_t jdksnet_rawsock_recv( struct jdksnet_rawsock *self, struct jdksavdecc_frame *frame );

int jdksnet_rawsock_join_multicast( struct jdksnet_rawsock *self, const struct jdksavdecc_eui48 *multicast_mac );

void jdksnet_rawsock_set_socket_nonblocking( struct jdksnet_rawsock *self );

#ifdef __cplusplus
}
#endif
