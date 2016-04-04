#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

//  Forward declarations:
extern  BOOL GetProcessList( );
extern BOOL  ListProcessModules( DWORD dwPID );
extern BOOL ListProcessThreads( DWORD dwOwnerPID );
extern void printError( TCHAR* msg );

extern DWORD QyGetProcessID(TCHAR* msg);