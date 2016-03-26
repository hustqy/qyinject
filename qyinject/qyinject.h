#if !defined INJCODE_H
#define INJCODE_H

int GetWindowTextRemoteA (HANDLE hProcess, HWND hWnd, LPSTR  lpString);
int GetWindowTextRemoteW (HANDLE hProcess, HWND hWnd, LPWSTR lpString);


#ifdef UNICODE
#define GetWindowTextRemote GetWindowTextRemoteW
#else
#define GetWindowTextRemote GetWindowTextRemoteA
#endif // !UNICODE

#endif // !defined(INJCODE_H)
