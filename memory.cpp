#include "memory.h"

DWORD memory::getProcess(const wchar_t* procname)
{
	DWORD procId = 0; // создаем переменную
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // получаем хэндл всех открытых процессов
	if (hSnap != INVALID_HANDLE_VALUE) // делаем проверку на пригодность хэндла
	{
		PROCESSENTRY32 entry; // создаем переменную из класса PROCESSENTRY32
		entry.dwSize = sizeof(PROCESSENTRY32); // присваиваем размер переменной

		if (Process32First(hSnap, &entry)) // делаем проверку на получение первого процесса
		{
			do
			{
				if (!_wcsicmp(entry.szExeFile, procname)) // делаем проверку на сравнение строк ( если строки равны, будет возврат false )
				{
					procId = entry.th32ProcessID; // присваиваем нужны нам процесс
					this->hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);
					break; // выходим из цикла
				}
			} while (Process32Next(hSnap, &entry)); // если проверка не пройдена, то берем следующий процесс
		}
	}
	CloseHandle(hSnap); // закрываем хэндл
	return procId; // возвращаем номер процесса - получаем номер процесса
}

DWORD memory::getModule(DWORD procId, const wchar_t* modulename)
{
	DWORD baseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, procId);// получаем хэндл всех открытых модулей
	if (hSnap != INVALID_HANDLE_VALUE) // делаем проверку на пригодность хэндла
	{
		MODULEENTRY32 entry; // создаем переменную из класса MODULEENTRY32
		entry.dwSize = sizeof(MODULEENTRY32); // присваиваем размер переменной

		if (Module32First(hSnap, &entry)) // делаем проверку на получение первого модуля
		{
			do
			{
				if (!_wcsicmp(entry.szModule, modulename)) // делаем проверку на сравнение строк ( если строки равны, будет возврат false )
				{
					baseAddress = (DWORD)entry.modBaseAddr; // присваиваем адрес в переменную
					break; // выходим из цикла
				}
			} while (Module32Next(hSnap, &entry)); // если проверка не пройдена, то берем следующий модуль
		}
	}
	CloseHandle(hSnap); // закрываем хэндл
	return baseAddress; // возвращаем адрес модуля - получаем адрес модуля
}

DWORD memory::GetOffsetsAddress(DWORD ptr, std::vector<uint32_t> offsets)
{
	DWORD addr = ptr;
	for (uint32_t i = 0; i < offsets.size(); ++i)
	{
		ReadProcessMemory(this->hProc, (BYTE*)(addr + offsets.at(i)), &offsets.at(i), sizeof(offsets.at(i)), 0);
	}
	return addr;
}