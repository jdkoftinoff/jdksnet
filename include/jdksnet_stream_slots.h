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

struct jdksnet_stream_slots
{
    /**
     * Ask the object to terminate
     */
    void ( *terminate )( struct jdksnet_stream_slots *self );

    /**
     * Ask the object to send signals to the destination_signals object
     */
    void ( *connect_signals )( struct jdksnet_stream_slots *self, struct jdksnet_stream_signals *destination_signals );

    /**
     * Ask the object to disconnect sending of signals to the destinaiton_signals object
     */
    void ( *disconnect_signals )( struct jdksnet_stream_slots *self, struct jdksnet_stream_signals *destination_signals );

    /**
     * External Networking Request: The client object wants to wake up when the socket is writable
     */
    void ( *wake_on_writable )( struct jdksnet_stream_slots *self, bool enable );

    /**
     * External Networking Request: The client object wants to connect to a destination
     */
    void ( *connect )( struct jdksnet_stream_slots *self, struct sockaddr const *addr, socklen_t addr_len );

    /**
     * External Networking Request: The client object wants to close the socket
     */
    void ( *close )( struct jdksnet_stream_slots *self, struct jdksnet_stream_signals *net_event_handler );

    /**
     * External Networking Request: The client object wants to send a frame
     */
    ssize_t ( *send )( struct jdksnet_stream_slots *self, const struct jdksavdecc_frame *frame );

    /**
     * External Networking Request: The client object wants to be woken up in the future
     */
    void ( *wake_up )( struct jdksnet_stream_slots *self, uint64_t delta_time_in_microseconds );
};

#ifdef __cplusplus
}
#endif
