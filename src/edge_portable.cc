#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <intrin.h>

#include <string>
#include <string_view>
#include <vector>

#include "detours.h"

// ============================================================
// Forward exports of the real version.dll
// NOP_FUNC provides enough bytes for Detours to patch the stub
// ============================================================
#define NOP_FUNC      \
  {                   \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    __nop();          \
    return __COUNTER__; \
  }

#define EXPORT(name) \
  extern "C" __declspec(dllexport) int __cdecl name() NOP_FUNC

#pragma comment(linker, "/export:GetFileVersionInfoA=_GetFileVersionInfoA_fw,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=_GetFileVersionInfoByHandle_fw,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=_GetFileVersionInfoExA_fw,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=_GetFileVersionInfoExW_fw,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=_GetFileVersionInfoSizeA_fw,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=_GetFileVersionInfoSizeExA_fw,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=_GetFileVersionInfoSizeExW_fw,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=_GetFileVersionInfoSizeW_fw,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=_GetFileVersionInfoW_fw,@9")
#pragma comment(linker, "/export:VerFindFileA=_VerFindFileA_fw,@10")
#pragma comment(linker, "/export:VerFindFileW=_VerFindFileW_fw,@11")
#pragma comment(linker, "/export:VerInstallFileA=_VerInstallFileA_fw,@12")
#pragma comment(linker, "/export:VerInstallFileW=_VerInstallFileW_fw,@13")
#pragma comment(linker, "/export:VerLanguageNameA=_VerLanguageNameA_fw,@14")
#pragma comment(linker, "/export:VerLanguageNameW=_VerLanguageNameW_fw,@15")
#pragma comment(linker, "/export:VerQueryValueA=_VerQueryValueA_fw,@16")
#pragma comment(linker, "/export:VerQueryValueW=_VerQueryValueW_fw,@17")

EXPORT(_GetFileVersionInfoA_fw)
EXPORT(_GetFileVersionInfoByHandle_fw)
EXPORT(_GetFileVersionInfoExA_fw)
EXPORT(_GetFileVersionInfoExW_fw)
EXPORT(_GetFileVersionInfoSizeA_fw)
EXPORT(_GetFileVersionInfoSizeExA_fw)
EXPORT(_GetFileVersionInfoSizeExW_fw)
EXPORT(_GetFileVersionInfoSizeW_fw)
EXPORT(_GetFileVersionInfoW_fw)
EXPORT(_VerFindFileA_fw)
EXPORT(_VerFindFileW_fw)
EXPORT(_VerInstallFileA_fw)
EXPORT(_VerInstallFileW_fw)
EXPORT(_VerLanguageNameA_fw)
EXPORT(_VerLanguageNameW_fw)
EXPORT(_VerQueryValueA_fw)
EXPORT(_VerQueryValueW_fw)

// ============================================================
// Helpers
// ============================================================
static std::wstring GetAppDir() {
  wchar_t path[MAX_PATH];
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  PathRemoveFileSpecW(path);
  return path;
}

static std::wstring GetIniPath() {
  return GetAppDir() + L"\\chrome++.ini";
}

static std::wstring GetIniString(const wchar_t* section, const wchar_t* key,
                                  const wchar_t* def = L"") {
  wchar_t buf[4096];
  GetPrivateProfileStringW(section, key, def, buf, 4096, GetIniPath().c_str());
  return buf;
}

static std::wstring ExpandPath(std::wstring path) {
  const std::wstring app_dir = GetAppDir();
  const std::wstring token = L"%app%";
  size_t pos = 0;
  while ((pos = path.find(token, pos)) != std::wstring::npos) {
    path.replace(pos, token.size(), app_dir);
    pos += app_dir.size();
  }
  wchar_t expanded[MAX_PATH * 2];
  if (ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH * 2))
    path = expanded;
  wchar_t full[MAX_PATH];
  if (PathCanonicalizeW(full, path.c_str()))
    path = full;
  return path;
}

static std::wstring QuoteIfNeeded(const std::wstring& s) {
  if (s.find(L' ') != std::wstring::npos && s[0] != L'"')
    return L'"' + s + L'"';
  return s;
}

// ============================================================
// UpdateProcThreadAttribute hook
// Strips BlockNonMicrosoftBinaries so unsigned DLLs load in child processes
// ============================================================
static auto RawUpdateProcThreadAttribute = UpdateProcThreadAttribute;

static const DWORD64 kBlockNonMicrosoftBinariesAlwaysOn = 0x00000001ui64 << 44;
static const DWORD64 kWin32kSystemCallDisableAlwaysOn   = 0x00000001ui64 << 28;

static BOOL WINAPI MyUpdateProcThreadAttribute(
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    DWORD dwFlags, DWORD_PTR Attribute,
    PVOID lpValue, SIZE_T cbSize,
    PVOID lpPreviousValue, PSIZE_T lpReturnSize) {
  if (Attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY &&
      cbSize >= sizeof(DWORD64)) {
    PDWORD64 policy = static_cast<PDWORD64>(lpValue);
    policy[0] &= ~kBlockNonMicrosoftBinariesAlwaysOn;
  }
  return RawUpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute,
                                      lpValue, cbSize, lpPreviousValue,
                                      lpReturnSize);
}

// ============================================================
// CryptProtect/Unprotect hooks — portable profile
// ============================================================
static auto RawCryptProtectData   = CryptProtectData;
static auto RawCryptUnprotectData = CryptUnprotectData;

static BOOL WINAPI MyCryptProtectData(
    DATA_BLOB* pDataIn, LPCWSTR, DATA_BLOB*, PVOID,
    CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB* pDataOut) {
  pDataOut->cbData = pDataIn->cbData;
  pDataOut->pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, pDataOut->cbData));
  if (!pDataOut->pbData) return FALSE;
  memcpy(pDataOut->pbData, pDataIn->pbData, pDataOut->cbData);
  return TRUE;
}

static BOOL WINAPI MyCryptUnprotectData(
    DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy,
    PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
    DWORD dwFlags, DATA_BLOB* pDataOut) {
  if (RawCryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy,
                             pvReserved, pPromptStruct, dwFlags, pDataOut))
    return TRUE;
  pDataOut->cbData = pDataIn->cbData;
  pDataOut->pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, pDataOut->cbData));
  if (!pDataOut->pbData) return FALSE;
  memcpy(pDataOut->pbData, pDataIn->pbData, pDataOut->cbData);
  return TRUE;
}

// ============================================================
// MV2 patch: set g_allow_mv2_for_testing = true
// https://source.chromium.org/chromium/chromium/src/+/main:extensions/browser/manifest_v2_experiment_manager.cc;l=41
//
// Locate getter+setter pair that both reference the same bool address:
//   getter: 0F B6 05 [off32] C3   (movzx eax, byte ptr [rip+X]; ret)
//   setter: 88 0D [off32]    C3   (mov byte ptr [rip+Y], cl;    ret)
// Both X and Y must resolve to the same address == g_allow_mv2_for_testing.
// ============================================================
// Must be called from Loader() — not DllMain — because g_allow_mv2_for_testing
// lives in chrome.dll which is not yet loaded during DLL_PROCESS_ATTACH.
static bool PatchMV2InModule(HMODULE hModule) {
  MODULEINFO mi{};
  if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi)))
    return false;

  auto base  = reinterpret_cast<PBYTE>(hModule);
  auto limit = base + mi.SizeOfImage - 8;

  auto resolve_rip = [](PBYTE insn, int offset_pos, int insn_len) -> PBYTE {
    INT32 off;
    memcpy(&off, insn + offset_pos, 4);
    return insn + insn_len + off;
  };

  for (PBYTE p = base; p < limit; ++p) {
    // getter: 0F B6 05 [off32] C3
    if (p[0] != 0x0F || p[1] != 0xB6 || p[2] != 0x05 || p[7] != 0xC3)
      continue;

    PBYTE bool_addr = resolve_rip(p, 3, 7);
    if (bool_addr < base || bool_addr >= base + mi.SizeOfImage) continue;
    if (*bool_addr != 0) continue;

    // Find matching setter: 88 0D [off32] C3 pointing to same address
    bool found_setter = false;
    for (PBYTE q = base; q < limit; ++q) {
      if (q[0] == 0x88 && q[1] == 0x0D && q[6] == 0xC3) {
        if (resolve_rip(q, 2, 6) == bool_addr) {
          found_setter = true;
          break;
        }
      }
    }
    if (!found_setter) continue;

    DWORD old;
    if (VirtualProtect(bool_addr, 1, PAGE_READWRITE, &old)) {
      *bool_addr = 1;
      VirtualProtect(bool_addr, 1, old, &old);
    }
    return true;
  }
  return false;
}

static void PatchMV2() {
  static const wchar_t* kCandidates[] = {
    L"chrome.dll", L"msedge.dll", nullptr
  };
  for (int i = 0; kCandidates[i]; ++i) {
    HMODULE h = GetModuleHandleW(kCandidates[i]);
    if (h && PatchMV2InModule(h)) return;
  }
}

// Hook LoadLibraryExW to catch chrome.dll/msedge.dll the moment they load
static auto RawLoadLibraryExW = LoadLibraryExW;

static HMODULE WINAPI MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile,
                                        DWORD dwFlags) {
  HMODULE h = RawLoadLibraryExW(lpLibFileName, hFile, dwFlags);
  if (h && lpLibFileName) {
    const wchar_t* name = PathFindFileNameW(lpLibFileName);
    if (_wcsicmp(name, L"chrome.dll") == 0 ||
        _wcsicmp(name, L"msedge.dll") == 0) {
      PatchMV2InModule(h);
      // Unhook ourselves — only need to patch once
      DetourTransactionBegin();
      DetourUpdateThread(GetCurrentThread());
      DetourDetach(reinterpret_cast<LPVOID*>(&RawLoadLibraryExW),
                   reinterpret_cast<void*>(MyLoadLibraryExW));
      DetourTransactionCommit();
    }
  }
  return h;
}

static void InstallLoadLibraryHook() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<LPVOID*>(&RawLoadLibraryExW),
               reinterpret_cast<void*>(MyLoadLibraryExW));
  DetourTransactionCommit();
}

// ============================================================
// Command-line builder — mirrors portable.cc logic
// ============================================================
static std::wstring GetCommand(LPWSTR param) {
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(param, &argc);

  std::vector<std::wstring> args;
  args.reserve(argc + 16);
  // skip argv[0] (exe path)
  for (int i = 1; i < argc; ++i)
    args.emplace_back(argv[i]);
  if (argv) LocalFree(argv);

  // Append args from ini command_line=
  std::wstring extra = GetIniString(L"general", L"command_line");
  if (!extra.empty()) {
    std::wstring fake = L"x " + extra;
    int eargc = 0;
    LPWSTR* eargv = CommandLineToArgvW(fake.c_str(), &eargc);
    for (int i = 1; i < eargc; ++i)
      args.emplace_back(eargv[i]);
    if (eargv) LocalFree(eargv);
  }

  args.emplace_back(L"--portable");

  // Merge all --disable-features into one
  std::wstring combined_features;
  std::vector<std::wstring> final_args;
  final_args.reserve(args.size() + 4);
  bool has_user_data  = false;
  bool has_disk_cache = false;

  for (auto& arg : args) {
    if (arg.starts_with(L"--disable-features=")) {
      if (!combined_features.empty()) combined_features += L',';
      combined_features += arg.substr(wcslen(L"--disable-features="));
    } else {
      if (arg.starts_with(L"--user-data-dir="))  has_user_data  = true;
      if (arg.starts_with(L"--disk-cache-dir=")) has_disk_cache = true;
      final_args.push_back(arg);
    }
  }

  if (!combined_features.empty()) combined_features += L',';
  combined_features += L"WinSboxNoFakeGdiInit"
                       L",WebUIInProcessResourceLoading"
                       L",ExtensionManifestV2Disabled"
                       L",ExtensionManifestV2Unsupported"
                       L",ExtensionManifestV2DeprecationWarning";
  final_args.emplace_back(L"--disable-features=" + combined_features);

  if (!has_user_data) {
    std::wstring d = GetIniString(L"general", L"data_dir");
    if (!d.empty()) final_args.emplace_back(L"--user-data-dir=" + ExpandPath(d));
  }
  if (!has_disk_cache) {
    std::wstring c = GetIniString(L"general", L"cache_dir");
    if (!c.empty()) final_args.emplace_back(L"--disk-cache-dir=" + ExpandPath(c));
  }

  std::wstring result;
  for (auto& a : final_args) {
    if (!result.empty()) result += L' ';
    result += QuoteIfNeeded(a);
  }
  return result;
}

// ============================================================
// Entry point hook — mirrors chrome++.cc / portable.cc
// ============================================================
using Startup = int (*)();
static Startup ExeMain = nullptr;

static int Loader() {
  LPWSTR param = GetCommandLineW();
  if (!wcsstr(param, L"-type=")) {
    if (!wcsstr(param, L"--portable")) {
      // First launch: relaunch with portable args
      wchar_t exe_path[MAX_PATH];
      GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

      std::wstring args     = GetCommand(param);
      std::wstring cmdline  = QuoteIfNeeded(exe_path);
      if (!args.empty()) { cmdline += L' '; cmdline += args; }

      std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
      buf.push_back(L'\0');

      std::wstring app_dir = GetAppDir();
      STARTUPINFOW si{ .cb = sizeof(si), .dwFlags = STARTF_USESHOWWINDOW,
                       .wShowWindow = SW_SHOWNORMAL };
      PROCESS_INFORMATION pi{};
      if (CreateProcessW(exe_path, buf.data(), nullptr, nullptr, FALSE, 0,
                         nullptr, app_dir.c_str(), &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ExitProcess(0);
      }
    }
    // Second launch (--portable present): install LoadLibrary hook to patch MV2
    // when chrome.dll/msedge.dll is loaded (they load after ExeMain returns)
    InstallLoadLibraryHook();
  }
  return ExeMain();
}

static void InstallLoader() {
  MODULEINFO mi{};
  GetModuleInformation(GetCurrentProcess(), GetModuleHandleW(nullptr), &mi,
                       sizeof(mi));
  ExeMain = reinterpret_cast<Startup>(mi.EntryPoint);

  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<LPVOID*>(&ExeMain),
               reinterpret_cast<void*>(Loader));
  DetourTransactionCommit();
}

// ============================================================
// Forward real version.dll — mirrors hijack.cc LoadVersion()
// ============================================================
static void LoadSysDll(HINSTANCE hModule) {
  wchar_t sys_dir[MAX_PATH];
  GetSystemDirectoryW(sys_dir, MAX_PATH);
  std::wstring dll_path = std::wstring(sys_dir) + L"\\version.dll";

  HINSTANCE real = LoadLibraryW(dll_path.c_str());
  if (!real) return;

  auto image_base = reinterpret_cast<PBYTE>(hModule);
  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
  auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(image_base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return;
  auto exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      image_base + nt->OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  auto names    = reinterpret_cast<DWORD*>(image_base + exp->AddressOfNames);
  auto funcs    = reinterpret_cast<DWORD*>(image_base + exp->AddressOfFunctions);
  auto ordinals = reinterpret_cast<WORD*>(image_base + exp->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    auto fn_name  = reinterpret_cast<char*>(image_base + names[i]);
    auto real_fn  = reinterpret_cast<PBYTE>(GetProcAddress(real, fn_name));
    auto stub     = reinterpret_cast<PBYTE>(image_base + funcs[ordinals[i]]);
    if (!real_fn) continue;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<LPVOID*>(&stub), real_fn);
    DetourTransactionCommit();
  }
}

// ============================================================
// DllMain
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID) {
  if (dwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);

    LoadSysDll(hModule);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<LPVOID*>(&RawUpdateProcThreadAttribute),
                 reinterpret_cast<void*>(MyUpdateProcThreadAttribute));
    DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptProtectData),
                 reinterpret_cast<void*>(MyCryptProtectData));
    DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptUnprotectData),
                 reinterpret_cast<void*>(MyCryptUnprotectData));
    DetourTransactionCommit();

    InstallLoader();
  }
  return TRUE;
}
