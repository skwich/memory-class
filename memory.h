#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

class memory
{
private:
	HANDLE hProc;

public:
	memory()
	{
		this->hProc = INVALID_HANDLE_VALUE;
	}

	~memory()
	{
		CloseHandle(hProc);
	}

	DWORD getProcess(const wchar_t* procname);
	uintptr_t getModule(DWORD procId, const wchar_t* modulename);
	uintptr_t GetOffsetsAddress(uintptr_t ptr, std::vector<uint32_t> offsets);
	
	template <class T>
	T readmem(T addr)
	{
		ReadProcessMemory(this->hProc, (T*)addr, &addr, sizeof(addr), 0);
		return addr;
	}

	template <class T>
	void writemem(T addr, T value)
	{
		WriteProcessMemory(this->hProc, (T*)addr, &value, sizeof(value), 0);
	}
};