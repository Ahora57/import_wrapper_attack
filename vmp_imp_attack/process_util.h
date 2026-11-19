#ifndef PROCESS_UTIL
#define PROCESS_UTIL 1 

#include "struct.h" 


NTSTATUS
NTAPI
NtQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL
);

namespace process_help
{
	PVOID nt_query_system_information = NULL; 
	namespace crt_wrapper
	{
		INLINE auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		}

		INLINE auto free(PVOID ptr) -> VOID
		{
			if (ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}

		INLINE auto wtolower(INT c) -> INT
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			return c;
		}

		INLINE auto wstricmp(CONST WCHAR* cs, CONST WCHAR* ct) -> INT
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == NULL && *ct == NULL) return NULL;
					if (*cs == NULL || *ct == NULL) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}

	}



	auto get_process_id(CONST WCHAR* process_name) -> uint32_t
	{
		ULONG ret_lenght = NULL;
		uint32_t process_id = NULL;
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		HMODULE ntdll_base = NULL;
		PVOID buffer = NULL;
		PSYSTEM_PROCESS_INFORMATION process_info = NULL;


		if (!nt_query_system_information)
		{
			ntdll_base = GetModuleHandleW(L"ntdll.dll");
			nt_query_system_information = GetProcAddress(ntdll_base, "NtQuerySystemInformation");
		}

		nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);

		while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (buffer != NULL)
				crt_wrapper::free(buffer);

			buffer = crt_wrapper::malloc(ret_lenght);
			nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_system_information)(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
		}

		if (!NT_SUCCESS(nt_status))
		{
			crt_wrapper::free(buffer);
			return NULL;
		}

		process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
		while (process_info->NextEntryOffset)
		{

			if (crt_wrapper::wstricmp(process_info->ImageName.Buffer, process_name) == NULL)
			{
				process_id = reinterpret_cast<uint32_t>(process_info->UniqueProcessId);
				break;
			}
			process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset);
		}
		crt_wrapper::free(buffer);
		return process_id;

	}

	auto get_module_address(uint32_t proc_id, CONST WCHAR* modName) -> uint8_t*
	{
		uint8_t* module_address = NULL;
		HANDLE snap_mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);

		if (snap_mod != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W mod_entry = { NULL };
			mod_entry.dwSize = sizeof(mod_entry);
			if (Module32FirstW(snap_mod, &mod_entry))
			{
				do
				{
					if (crt_wrapper::wstricmp(mod_entry.szModule, modName) == NULL)
					{
						module_address = mod_entry.modBaseAddr;
						break;
					}
				} while (Module32NextW(snap_mod, &mod_entry));
			}
		}
		CloseHandle(snap_mod);
		return module_address;
	}

	auto get_module_size(uint32_t proc_id, CONST WCHAR* modName) -> uint32_t
	{
		uint32_t module_size = NULL;
		HANDLE snap_mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);

		if (snap_mod != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W mod_entry = { NULL };
			mod_entry.dwSize = sizeof(mod_entry);
			if (Module32FirstW(snap_mod, &mod_entry))
			{
				do
				{
					if (crt_wrapper::wstricmp(mod_entry.szModule, modName) == NULL)
					{
						module_size = mod_entry.modBaseSize;
						break;
					}
				} while (Module32NextW(snap_mod, &mod_entry));
			}
		}
		CloseHandle(snap_mod);
		return module_size;
	}

	NO_INLINE auto get_module_list_proc(uint32_t proc_id, std::vector< MODULE_INFO>& mod_list) -> BOOLEAN
	{
		uint32_t count_mod = NULL;
		MODULE_INFO cur_mod = { NULL };
		HANDLE access = NULL;
		HANDLE snap_mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id);
		PIMAGE_NT_HEADERS nt_headers = NULL;
		PIMAGE_SECTION_HEADER sec = NULL;

		if (snap_mod != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W mod_entry = { NULL };
			mod_entry.dwSize = sizeof(mod_entry);
			access = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
			if (access != INVALID_HANDLE_VALUE)
			{
				if (Module32FirstW(snap_mod, &mod_entry))
				{
					do
					{
						cur_mod.orig_addr_mem = mod_entry.modBaseAddr;
						cur_mod.coped_size = mod_entry.modBaseSize;
						cur_mod.mod_name = mod_entry.szModule;
						cur_mod.coped_mem = reinterpret_cast<uint8_t*>(crt_wrapper::malloc(cur_mod.coped_size + 0x1000));
						if (cur_mod.coped_mem && ReadProcessMemory(access, cur_mod.orig_addr_mem, cur_mod.coped_mem, cur_mod.coped_size, NULL))
						{
							nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(cur_mod.coped_mem) + reinterpret_cast<IMAGE_DOS_HEADER*>(cur_mod.coped_mem)->e_lfanew);
							if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
							{
								if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
								{
									cur_mod.is_any_export = TRUE;
								}
							}
						}
						else
						{
							//lazy fix PE + resurved  mem + .text
							if (GetLastError() == ERROR_PARTIAL_COPY)
							{
								//if addr exist in process, don't copy with reserve
								if (reinterpret_cast<uint8_t*>( GetModuleHandleW(cur_mod.mod_name.c_str())) == cur_mod.orig_addr_mem)
								{
									cur_mod.coped_mem = cur_mod.orig_addr_mem;
									nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(cur_mod.coped_mem) + reinterpret_cast<IMAGE_DOS_HEADER*>(cur_mod.coped_mem)->e_lfanew);
									if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
									{
										if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
										{
											cur_mod.is_any_export = TRUE;
										}
									}
								} 
								else
								{
									printf("need fix!\n");
									__debugbreak();
								}
							}
 
						}
						mod_list.push_back(cur_mod);
						count_mod++;
					} while (Module32NextW(snap_mod, &mod_entry));
				}
				CloseHandle(access);
			}
	}
		CloseHandle(snap_mod);
		return count_mod;
	}
	auto get_process_inform(proc_info& proc_inform, CONST WCHAR* proc_name, CONST WCHAR* mod_name) -> BOOLEAN
	{
		BOOLEAN is_get_sec = FALSE;
		PIMAGE_NT_HEADERS nt_headers = NULL;
		PIMAGE_SECTION_HEADER sec = NULL;
		HANDLE access = INVALID_HANDLE_VALUE;
		SEC_INFO cur_sec_info = { NULL };
		proc_inform.sec_list.clear();

		proc_inform.proc_id = process_help::get_process_id(proc_name);
 		if (proc_inform.proc_id)
		{
			proc_inform.orig_addr_mem = process_help::get_module_address(proc_inform.proc_id, mod_name);
			if (proc_inform.orig_addr_mem)
			{
				proc_inform.coped_size = process_help::get_module_size(proc_inform.proc_id, mod_name);

				access = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_inform.proc_id);
				if (access)
				{ 
					proc_inform.coped_mem = reinterpret_cast<uint8_t*>(crt_wrapper::malloc(proc_inform.coped_size + 0x1000));
					if (proc_inform.coped_mem && ReadProcessMemory(access, proc_inform.orig_addr_mem, proc_inform.coped_mem, proc_inform.coped_size, NULL))
					{
						nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(proc_inform.coped_mem) + reinterpret_cast<IMAGE_DOS_HEADER*>(proc_inform.coped_mem)->e_lfanew);
						if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
						{
							sec = IMAGE_FIRST_SECTION(nt_headers);

							for (size_t sec_id = NULL; sec_id < nt_headers->FileHeader.NumberOfSections; sec_id++)
							{
								cur_sec_info.sec_type_info = sec_type_unk;
								cur_sec_info.raw = sec[sec_id].PointerToRawData;
								cur_sec_info.raw_size = sec[sec_id].SizeOfRawData;
								cur_sec_info.rva = sec[sec_id].VirtualAddress;
								cur_sec_info.virt_size = sec[sec_id].Misc.VirtualSize;
								cur_sec_info.sec_addr_coped = reinterpret_cast<uint8_t*>(proc_inform.coped_mem) + sec[sec_id].VirtualAddress;
								cur_sec_info.characteris = sec[sec_id].Characteristics;
								proc_inform.sec_list.push_back(cur_sec_info);
							}
							proc_inform.ep = nt_headers->OptionalHeader.AddressOfEntryPoint;
							is_get_sec = TRUE; 
						}
						else
						{
							if (proc_inform.coped_mem)
							{
								crt_wrapper::free(proc_inform.coped_mem);
							}
						}
					}
					else
					{
						printf("last error get_process_inform ->\t%p\n", GetLastError());

						if (proc_inform.coped_mem)
						{
							crt_wrapper::free(proc_inform.coped_mem);
						}
					}
				}
				CloseHandle(access);
			} 
		}		
		return is_get_sec;
	}

}


#endif // !PROCESS_UTIL