#include "memory.h"

DWORD memory::getProcess(const wchar_t* procname)
{
	DWORD procId = 0; // ������� ����������
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // �������� ����� ���� �������� ���������
	if (hSnap != INVALID_HANDLE_VALUE) // ������ �������� �� ����������� ������
	{
		PROCESSENTRY32 entry; // ������� ���������� �� ������ PROCESSENTRY32
		entry.dwSize = sizeof(PROCESSENTRY32); // ����������� ������ ����������

		if (Process32First(hSnap, &entry)) // ������ �������� �� ��������� ������� ��������
		{
			do
			{
				if (!_wcsicmp(entry.szExeFile, procname)) // ������ �������� �� ��������� ����� ( ���� ������ �����, ����� ������� false )
				{
					procId = entry.th32ProcessID; // ����������� ����� ��� �������
					this->hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
					break; // ������� �� �����
				}
			} while (Process32Next(hSnap, &entry)); // ���� �������� �� ��������, �� ����� ��������� �������
		}
	}
	CloseHandle(hSnap); // ��������� �����
	return procId; // ���������� ����� �������� - �������� ����� ��������
}

uintptr_t memory::getModule(DWORD procId, const wchar_t* modulename)
{
	uintptr_t baseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, 0);// �������� ����� ���� �������� �������
	if (hSnap != INVALID_HANDLE_VALUE) // ������ �������� �� ����������� ������
	{
		MODULEENTRY32 entry; // ������� ���������� �� ������ MODULEENTRY32
		entry.dwSize = sizeof(MODULEENTRY32); // ����������� ������ ����������

		if (Module32First(hSnap, &entry)) // ������ �������� �� ��������� ������� ������
		{
			do
			{
				if (!_wcsicmp(entry.szModule, modulename)) // ������ �������� �� ��������� ����� ( ���� ������ �����, ����� ������� false )
				{
					baseAddress = *(uintptr_t*)entry.modBaseAddr; // ����������� ����� � ����������
					break; // ������� �� �����
				}
			} while (Module32Next(hSnap, &entry)); // ���� �������� �� ��������, �� ����� ��������� ������
		}
	}
	CloseHandle(hSnap); // ��������� �����
	return baseAddress; // ���������� ����� ������ - �������� ����� ������
}

uintptr_t memory::GetOffsetsAddress(uintptr_t ptr, std::vector<uint32_t> offsets)
{
	uintptr_t addr = ptr;
	for (uint32_t i = 0; i < offsets.size(); ++i)
	{
		ReadProcessMemory(this->hProc, (BYTE*)(addr + offsets.at(i)), &offsets.at(i), sizeof(offsets.at(i)), 0);
	}
	return addr;
}