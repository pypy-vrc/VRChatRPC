#pragma comment(linker, "/SECTION:.shared,RWS")
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

typedef LONG (__stdcall *RtlAdjustPrivilege)(
	IN ULONG Privilege,
	IN BOOLEAN Enable,
	IN BOOLEAN Client,
	OUT PBOOLEAN WasEnabled
);
typedef void* (__cdecl *SteamClient)(void);
typedef int (__cdecl *SteamAPI_GetHSteamUser)(void);
typedef int (__cdecl *SteamAPI_GetHSteamPipe)(void);
typedef void* (__cdecl *SteamAPI_ISteamClient_GetISteamUser)(void *, int, int, const char *);
typedef void* (__cdecl *SteamAPI_ISteamClient_GetISteamFriends)(void *, int, int, const char *);
typedef int (__cdecl *SteamAPI_ISteamUser_GetAuthSessionTicket)(void *, void *, int, int *);
typedef const char* (__cdecl *SteamAPI_ISteamFriends_GetPersonaName)(void *);

static HMODULE instance_;

#pragma data_seg(".shared")
static int auth_bytes_ = 0;
static char auth_[1024] = { 0, };
static char nick_[128] = { 0, };
#pragma data_seg()

void dbg(const char *fmt, ...)
{
	char a[1024];
	wvsprintf(a, fmt, (char *)&fmt + sizeof(fmt));
	OutputDebugString(a);
}

__declspec(dllexport) BOOL VRChatRPC_000(void)
{
	BOOL result = 0;
	BOOLEAN state;
	RtlAdjustPrivilege _RtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(GetModuleHandle("NTDLL"), "RtlAdjustPrivilege");
	if (_RtlAdjustPrivilege) {
		_RtlAdjustPrivilege(20 /*SE_DEBUG_PRIVILEGE*/, TRUE, FALSE, &state);
		HWND hwnd = FindWindow("UnityWndClass", "VRChat");
		if (hwnd) {
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);
			if (pid) {
				HWND process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				if (process) {
					LPVOID m = VirtualAllocEx(process, NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
					if (m) {
						char a[1024];
						if (GetModuleFileName(instance_, a, 1024)) {
							if (WriteProcessMemory(process, m, a, 1024, NULL)) {
								HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, m, 0, NULL);
								if (thread) {
									WaitForSingleObject(thread, INFINITE);
									CloseHandle(thread);
									result = TRUE;
								}
							}
							VirtualFreeEx(process, m, 0, MEM_RELEASE);
						}
						CloseHandle(process);
					}
				}
			}
		}
		_RtlAdjustPrivilege(20 /*SE_DEBUG_PRIVILEGE*/, FALSE, FALSE, &state);
	}
	/*dbg("result = %d", result);
	dbg("auth_ = %d", auth_bytes_);
	dbg("nick_ = {%s}", nick_);*/
	return result;
}

__declspec(dllexport) int VRChatRPC_001(void *out, int size)
{
	if (size >= auth_bytes_) {
		memcpy(out, auth_, auth_bytes_);
		return auth_bytes_;
	}
	return 0;
}

__declspec(dllexport) const char* VRChatRPC_002(void)
{
	return nick_;
}

#if 0
__declspec(dllexport) void CALLBACK Run(HWND hwnd, HINSTANCE instance, LPSTR arg, int show)
{
	VRChatRPC_000();
}
#endif

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_DETACH) {
		return TRUE;
	}
	if (reason == DLL_PROCESS_ATTACH) {
		instance_ = instance;
		DisableThreadLibraryCalls(instance);
		{
			BOOL result = TRUE;
			const BYTE *p = (char *)NtCurrentTeb();
			p = *(BYTE **)&p[sizeof(p) * 12]; // TEB->PEB
			p = *(BYTE **)&p[sizeof(p) * 3]; // PEB->PEB_LDR_DATA
			p = *(BYTE **)&p[sizeof(p) * 3 + 8]; // PEB_LDR_DATA->InMemoryOrderModuleList.FLink
			for (;;) {
				DWORD n = *(WORD *)&p[sizeof(p) * 9]; // LDR_MODULE->BaseDllName.Length
				if (!n)
					break;
				const char *c = *(char **)&p[sizeof(p) * 10]; // LDR_MODULE->BaseDllName.Buffer
				DWORD i = 0;
				do
					i = _rotr(i ^ (*c++ & 223), 7) + 1;
				while (--n);
				// dbg("%p %08X (%S)", *(HMODULE *)&p[sizeof(p) * 4], i, *(wchar_t **)&p[sizeof(p) * 10]);
				if (i == 0x048627FB) { // steam_api64.dll
					PROC proc;
					HMODULE m = *(HMODULE *)&p[sizeof(p) * 4];
					void *pClient = NULL;
					if (proc = GetProcAddress(m, "SteamClient")) {
						pClient = ((SteamClient)proc)();
						if (pClient) {
							int hSteamUser = 0;
							int hSteamPipe = 0;
							void *pSteamUser = NULL;
							void *pSteamFriends = NULL;
							if (proc = GetProcAddress(m, "SteamAPI_GetHSteamUser")) {
								hSteamUser = ((SteamAPI_GetHSteamUser)proc)();
							}
							if (proc = GetProcAddress(m, "SteamAPI_GetHSteamPipe")) {
								hSteamPipe = ((SteamAPI_GetHSteamUser)proc)();
							}
							if (hSteamUser && hSteamPipe) {
								if (proc = GetProcAddress(m, "SteamAPI_ISteamClient_GetISteamUser")) {
									pSteamUser = ((SteamAPI_ISteamClient_GetISteamUser)proc)(pClient, hSteamUser, hSteamPipe, "SteamUser019");
									if (pSteamUser &&
										(proc = GetProcAddress(m, "SteamAPI_ISteamUser_GetAuthSessionTicket"))) {
										((SteamAPI_ISteamUser_GetAuthSessionTicket)proc)(pSteamUser, auth_, sizeof(auth_), &auth_bytes_);
									}
								}
								if (proc = GetProcAddress(m, "SteamAPI_ISteamClient_GetISteamFriends")) {
									pSteamFriends = ((SteamAPI_ISteamClient_GetISteamFriends)proc)(pClient, hSteamUser, hSteamPipe, "SteamFriends015");
									if (pSteamFriends &&
										(proc = GetProcAddress(m, "SteamAPI_ISteamFriends_GetPersonaName"))) {
										const char *p = ((SteamAPI_ISteamFriends_GetPersonaName)proc)(pSteamFriends);
										if (p) {
											strncpy(nick_, p, sizeof(nick_));
											nick_[sizeof(nick_) - 1] = 0;
										}
									}
								}
							}
						}
					}
				} else if (i == 0x33A69712) { // VRChat.exe
					result = FALSE;
				}
				p = *(char **)p; // InMemoryOrderModuleList.FLink
			}
			return result;
		}
	}
	return FALSE;
}