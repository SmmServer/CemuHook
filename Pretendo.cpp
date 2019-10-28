#define PRIVATE
#include <ws2tcpip.h>
#include <Windows.h>
#include <string>
#include "debug.h"
#include "MinHook/MinHook.h"

extern "C" void __declspec(dllexport) inject() { }

decltype(&getaddrinfo) original_getaddrinfo;
decltype(&CreateFileW) original_CreateFileW;

static INT WSAAPI hook_getaddrinfo(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA      *ppResult
    )
{
    dlogp("'%s', '%s'", pNodeName, pServiceName);
    auto result = original_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    if(result == 0 && (strcmp(pNodeName, "account.nintendo.net") == 0
		|| strcmp(pNodeName, "wup-ama.app.nintendo.net") == 0
		|| strcmp(pNodeName, "discovery.olv.nintendo.net") == 0
		|| strcmp(pNodeName, "npts.app.nintendo.net") == 0
	))
    {
        for(PADDRINFOA pResult = *ppResult; pResult != nullptr; pResult = pResult->ai_next)
        {
            if(pResult->ai_family == AF_INET)
            {
                auto addr = (sockaddr_in*)pResult->ai_addr;
                auto& data = addr->sin_addr.S_un.S_un_b;
                dlogp("'%s': %u.%u.%u.%u -> 127.0.0.1",
                    pNodeName,
                    data.s_b1,
                    data.s_b2,
                    data.s_b3,
                    data.s_b4);
                data.s_b1 = 127;
                data.s_b2 = 0;
                data.s_b3 = 0;
                data.s_b4 = 1;
            }
        }
    }
    return result;
}

static HANDLE WINAPI hook_CreateFileW(
	__in     LPCWSTR lpFileName,
	__in     DWORD dwDesiredAccess,
	__in     DWORD dwShareMode,
	__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in     DWORD dwCreationDisposition,
	__in     DWORD dwFlagsAndAttributes,
	__in_opt HANDLE hTemplateFile
)
{
	if (lpFileName)
	{
		if (wcsstr(lpFileName, L"\\CACERT_NINTENDO_")
			|| wcsstr(lpFileName, L"/CACERT_NINTENDO_")
			|| wcsstr(lpFileName, L"seeprom.bin")
			|| wcsstr(lpFileName, L"otp.bin")
			|| wcsstr(lpFileName, L"account.dat")
		)
		{
			std::wstring proxyFilename = lpFileName;
			proxyFilename += L".proxy";
			dlogp("%S -> %S", lpFileName, proxyFilename.c_str());
			auto hFile = original_CreateFileW(proxyFilename.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
			if (hFile == INVALID_HANDLE_VALUE)
				dlogp("not found: %S", proxyFilename.c_str());
			return hFile;
		}
	}
	return original_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

template<class Func>
static MH_STATUS WINAPI MH_CreateHookApi(const wchar_t* pszModule, const char* pszProcName, Func* pDetour, Func*& ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, (LPVOID*)&ppOriginal);
}

//https://stackoverflow.com/a/21767578/1806760
struct handle_data
{
	unsigned long process_id;
	HWND window_handle;
};

static BOOL is_main_window(HWND handle)
{
	return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
}

static BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam)
{
	handle_data& data = *(handle_data*)lParam;
	unsigned long process_id = 0;
	GetWindowThreadProcessId(handle, &process_id);
	if (data.process_id != process_id || !is_main_window(handle))
		return TRUE;
	data.window_handle = handle;
	return FALSE;
}

static HWND find_main_window(DWORD process_id)
{
	handle_data data;
	data.process_id = process_id;
	data.window_handle = 0;
	EnumWindows(enum_windows_callback, (LPARAM)&data);
	return data.window_handle;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
#ifdef PRIVATE
		if (GetAsyncKeyState(VK_CONTROL))
		{
			dlogp("Proxy enabled!");
		}
		else
		{
			dlogp("Proxy disabled!");
			return FALSE;
		}
#endif // PRIVATE

		{
			char mutexName[128] = "";
			sprintf_s(mutexName, "Pretendo%u", GetCurrentProcessId());
			auto hMutex = CreateMutexA(nullptr, FALSE, mutexName);
			if (GetLastError() == ERROR_ALREADY_EXISTS)
			{
				dlogp("Already loaded!");
				return TRUE;
			}
		}

		if (MH_Initialize() != MH_OK)
		{
			dlogp("MH_Initialize failed");
			return FALSE;
		}
        if(MH_CreateHookApi(L"WS2_32.dll", "getaddrinfo", hook_getaddrinfo, original_getaddrinfo) != MH_OK)
		{
			dlogp("MH_CreateHook failed (getaddrinfo)");
			return FALSE;
		}
#ifdef PRIVATE
		if (MH_CreateHookApi(L"kernelbase.dll", "CreateFileW", hook_CreateFileW, original_CreateFileW) != MH_OK)
		{
			dlogp("MH_CreateHook failed (CreateFileW)");
			return FALSE;
		}
#endif // PRIVATE
		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		{
			dlogp("MH_EnableHook failed");
			return FALSE;
		}
		dlogp("Hooks installed!");

		auto hThread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD
		{
			while (true)
			{
				Sleep(50);

				auto cemuHwnd = find_main_window(GetCurrentProcessId());
				if (!cemuHwnd)
					continue;

				wchar_t windowTitle[256] = L"";
				GetWindowTextW(cemuHwnd, windowTitle, _countof(windowTitle));
				if (!wcsstr(windowTitle, L"Cemu") && !wcsstr(windowTitle, L"cemu"))
					continue;

				if (!wcsstr(windowTitle, L"smmdb"))
				{
					wcsncat_s(windowTitle, L" (smmdb)", _TRUNCATE);
					SetWindowTextW(cemuHwnd, windowTitle);
				}
				break;
			}
			return 0;
		}, nullptr, 0, nullptr);
		CloseHandle(hThread);
	}
	return TRUE;
}