#include "jdksnet_world.h"
#include "jdksnet.h"

static bool jdksnet_initted = false;

bool jdksnet_init( void )
{
    if ( !jdksnet_initted )
    {
#if defined( _WIN32 )
        WSADATA wsaData;
        WORD version;
        int error;
        version = MAKEWORD( 2, 2 );
        error = WSAStartup( version, &wsaData );
        if ( error != 0 )
        {
            return false;
        }
        if ( version != wsaData.wVersion )
        {
            return false;
        }
        jdksnet_initted = true;
        return true;
#elif defined( __linux__ ) || defined( __APPLE__ )
        struct sigaction act;
        act.sa_handler = SIG_IGN;
        sigemptyset( &act.sa_mask );
        act.sa_flags = 0;
        sigaction( SIGPIPE, &act, NULL );
        jdksnet_initted = true;
        return true;
#endif
    }
    return jdksnet_initted;
}
