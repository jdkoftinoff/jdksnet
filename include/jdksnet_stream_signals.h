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

struct jdksnet_stream_slots;
struct jdksnet_stream_signals;

struct jdksnet_stream_signals
{
    /**
     * External Networking Event: The socket was readable and some data was read
     */
    void ( *readable )( struct jdksnet_stream_signals *self, const struct jdksavdecc_frame *frame );

    /**
     * External Networking Event: The socket was connected
     */
    void ( *connected )( struct jdksnet_stream_signals *self,
                         const struct sockaddr *local_addr,
                         socklen_t local_addr_len,
                         const struct sockaddr *remote_addr,
                         socklen_t remote_addr_len );

    /**
     * External Networking Event: The socket is writable now
     */
    void ( *writable )( struct jdksnet_stream_signals *self );

    /**
     * External Networking Event: The socket was closed
     */
    void ( *closed )( struct jdksnet_stream_signals *self );

    /**
     * External Networking Event: Some time passed
     */
    void ( *tick )( struct jdksnet_stream_signals *self, jdksavdecc_timestamp_in_microseconds timestamp );
};

#ifdef __cplusplus
}
#endif
