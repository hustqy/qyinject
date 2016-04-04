
#include "stdafx.h"
#include <Windows.h>
#include "qyinject.h"
#include "processId.h"
#include <fstream>
#include <iostream>
using namespace std;
int _tmain(int argc, _TCHAR* argv[])
{


	DWORD PID = QyGetProcessID(TEXT("explorer.exe"));
	
	//parse image file that we wanted to inject into explorer.exe
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNT;
	PIMAGE_OPTIONAL_HEADER32 pOption;
	PIMAGE_SECTION_HEADER pSection;
	PIMAGE_FILE_HEADER pFileHeader;

	


	ifstream ifile ;
	ifile.open(argv[1],ios_base::binary| ios::ate);
	DWORD ImageSize = ifile.tellg();

	ifile.seekg(0);
	CHAR *buf = (char *) malloc(ImageSize+1) ;

	ifile.read(buf,ImageSize);
	pDos = (PIMAGE_DOS_HEADER) (buf);
	pNT = (PIMAGE_NT_HEADERS )(pDos->e_lfanew + (DWORD)buf);

	pOption = (PIMAGE_OPTIONAL_HEADER32 )( &pNT->OptionalHeader);
	pFileHeader = (PIMAGE_FILE_HEADER) &(pNT->FileHeader);
	pSection =( PIMAGE_SECTION_HEADER) ((DWORD)(pNT) + sizeof(IMAGE_NT_HEADERS) );


	
	DWORD dwStart = pOption->AddressOfEntryPoint;


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE, PID);		


	if( hProcess == NULL )
		_tprintf( TEXT("OpenProcess") );

	LPSTR mapAddress=(LPSTR)VirtualAllocEx(hProcess,0,pOption->SizeOfImage,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(hProcess, mapAddress, buf, pOption->SizeOfHeaders,0);

	 
	for (int i = 0 ;i<pFileHeader->NumberOfSections;i++)
	{
		PIMAGE_SECTION_HEADER psh = pSection +i ;
		WriteProcessMemory(hProcess, mapAddress + psh->VirtualAddress , (DWORD)(psh->PointerToRawData) + buf , psh->SizeOfRawData ,0);
	}


	DWORD delta =   (DWORD)mapAddress - pOption->ImageBase;


	// relocation
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

	CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)dwStart,0,0,0);

	return 0;
}

