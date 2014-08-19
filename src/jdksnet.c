#include "jdksnet_world.h"
#include "jdksnet.h"

static bool jdksnet_initted = false;

#ifdef _WIN32
#pragma comment( lib, "IPHLPAPI.lib" )
#pragma comment( lib, "Ws2_32.lib" )
#if defined( _MSC_VER ) || defined( _MSC_EXTENSIONS )
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif
#endif

int jdksnet_gettimeofday( struct timeval *tv )
{
#ifdef _WIN32
    FILETIME ft;
    unsigned __int64 tmpres = 0;
    static int tzflag;
    if ( NULL != tv )
    {
        GetSystemTimeAsFileTime( &ft );
        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;
        /*converting file time to unix epoch*/
        tmpres /= 10; /*convert into microseconds*/
        tmpres -= US_DELTA_EPOCH_IN_MICROSECS;
        tv->tv_sec = (long)( tmpres / 1000000UL );
        tv->tv_usec = (long)( tmpres % 1000000UL );
    }
    return 0;
#else
    return gettimeofday( tv, 0 );
#endif
}

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
