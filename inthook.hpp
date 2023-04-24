#pragma once
#include <Windows.h>
#include <vector>

#define INT3 0xCC

// todo: fix x64
namespace inthook {
	UCHAR original_call[]{
#ifdef _WIN64
		0x48, 0x89, 0xCE,                                           // mov rsi, rcx
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, function
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, inthook::ignore
		0xFF, 0xD0,                                                 // call rax
		0x48, 0x89, 0xF1,                                           // mov rcx, rsi
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, function
		0xFF, 0xE0                                                  // jmp rax
#elif _WIN32
		0x68, 0x00, 0x00, 0x00, 0x00, // push function
		0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, inthook::ignore
		0xFF, 0xD0,                   // call eax
		0x58,                         // pop eax
		0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, function 
		0xFF, 0xE0                    // jmp eax
#endif
	};

	struct info {
		PVOID function;
		PVOID hook;
		UCHAR old_byte;
		DWORD old_protect;
		BOOL ignore;
		BOOL disabled;
	};
	std::vector<info> hooks{};
	PVOID seh;

	LONG NTAPI vectored_handler(_EXCEPTION_POINTERS* exception) {
		DWORD ex_code = exception->ExceptionRecord->ExceptionCode;
		if (ex_code != EXCEPTION_BREAKPOINT && ex_code != EXCEPTION_SINGLE_STEP)
			return EXCEPTION_CONTINUE_SEARCH;

		for (info& cur : hooks) {
			if (cur.disabled)
				continue;

			if (ex_code == EXCEPTION_BREAKPOINT && exception->ExceptionRecord->ExceptionAddress == cur.function) {
				if (cur.ignore) {
					*(UCHAR*)cur.function = cur.old_byte; // set original byte
					exception->ContextRecord->EFlags |= 0x100; // signle step execution
					return EXCEPTION_CONTINUE_EXECUTION;
				}
#ifdef _WIN64
				exception->ContextRecord->Rip = (DWORD64)cur.hook;
#elif _WIN32
				exception->ContextRecord->Eip = (DWORD)cur.hook;
#endif
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else if (ex_code == EXCEPTION_SINGLE_STEP && cur.ignore) {
				exception->ContextRecord->EFlags &= ~0x100; // clear signle step flag
				*(UCHAR*)cur.function = INT3; // set int3 byte
				cur.ignore = false;
				return EXCEPTION_CONTINUE_EXECUTION;
			}

		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	bool ignore(void* function) {
		for (info& cur : hooks) {
			if (function != cur.function && cur.disabled)
				continue;
			cur.ignore = true;
			return true;
		}
		return false;
	}

	void* original(void* function) {
		void* address = VirtualAlloc(0, sizeof(original_call), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!address)
			return 0;
		memcpy(address, &original_call, sizeof(original_call));
#ifdef _WIN64
		*(DWORD64*)((DWORD64)address + 5) = (DWORD64)function;
		*(DWORD64*)((DWORD64)address + 15) = (DWORD64)inthook::ignore;
		*(DWORD64*)((DWORD64)address + 30) = (DWORD64)function;
#elif _WIN32
		*(DWORD*)((DWORD)address + 1) = (DWORD)function;
		*(DWORD*)((DWORD)address + 6) = (DWORD)inthook::ignore;
		*(DWORD*)((DWORD)address + 14) = (DWORD)function;
#endif
		return address;
	}

	bool create(void* function, void* hook, void* &original) {
		info new_hook = { function, hook };
		if (!VirtualProtect(new_hook.function, 0x1, PAGE_EXECUTE_READWRITE, &new_hook.old_protect))
			return false;

		new_hook.old_byte = *(UCHAR*)new_hook.function;
		*(UCHAR*)new_hook.function = INT3; // set int3 byte

		original = inthook::original(new_hook.function);
		if (!original)
			return false;

		hooks.push_back(new_hook);
		return true;
	}

	bool remove(void* function) {
		DWORD unused;
		for (info& cur : hooks) {
			if (function != cur.function && cur.disabled)
				continue;
			*(UCHAR*)cur.function = cur.old_byte; // set original byte
			VirtualProtect(cur.function, 0x1, cur.old_protect, &unused); // set original protect
			cur.disabled = true;
			return true;
		}
		return false;
	}

	bool init() {
		seh = AddVectoredExceptionHandler(1, vectored_handler);
		return seh != 0;
	}

	bool uninit() {
		DWORD unused;
		for (info& cur : hooks) {
			if (cur.disabled)
				continue;
			*(UCHAR*)cur.function = cur.old_byte; // set original byte
			VirtualProtect(cur.function, 0x1, cur.old_protect, &unused); // set original protect
			cur.disabled = true;
		}
		hooks.clear();
		return RemoveVectoredExceptionHandler(seh) != 0;
	}
}