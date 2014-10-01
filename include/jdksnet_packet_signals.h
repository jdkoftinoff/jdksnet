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

struct jdksnet_packet_slots;
struct jdksnet_packet_signals;

struct jdksnet_packet_signals
{
    void *m_target;

    /**
     * External Networking Event: The network port obtained link
     */
    void ( *link_up )( struct jdksnet_packet_signals *self, uint64_t bps, struct jdksavdecc_eui48 link_addr );

    /**
     * External Networking Event: The network port lost link
     */
    void ( *link_down )( struct jdksnet_packet_signals *self, uint64_t bps, struct jdksavdecc_eui48 link_addr );

    /**
     * External Networking Event: The socket was readable and some data was read
     */
    void ( *readable )( struct jdksnet_packet_signals *self, const struct jdksavdecc_frame *frame );

    /**
     * External Networking Event: The socket is writable now
     */
    void ( *writable )( struct jdksnet_packet_signals *self );

    /**
     * External Networking Event: The socket was closed
     */
    void ( *closed )( struct jdksnet_packet_signals *self );

    /**
     * External Networking Event: Some time passed
     */
    void ( *tick )( struct jdksnet_packet_signals *self, jdksavdecc_timestamp_in_microseconds timestamp );
};

#ifdef __cplusplus
}
#endif
