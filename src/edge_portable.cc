#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>

#include <string>
#include <string_view>
#include <vector>
#include <optional>

#include "detours.h"

// ============================================================
// Forward exports of the real version.dll
// ============================================================
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

// Stub functions — replaced at load time by LoadSysDll detours
#define STUB(name) \
  extern "C" __declspec(dllexport) int __cdecl name() { return 0; }

STUB(_GetFileVersionInfoA_fw)
STUB(_GetFileVersionInfoByHandle_fw)
STUB(_GetFileVersionInfoExA_fw)
STUB(_GetFileVersionInfoExW_fw)
STUB(_GetFileVersionInfoSizeA_fw)
STUB(_GetFileVersionInfoSizeExA_fw)
STUB(_GetFileVersionInfoSizeExW_fw)
STUB(_GetFileVersionInfoSizeW_fw)
STUB(_GetFileVersionInfoW_fw)
STUB(_VerFindFileA_fw)
STUB(_VerFindFileW_fw)
STUB(_VerInstallFileA_fw)
STUB(_VerInstallFileW_fw)
STUB(_VerLanguageNameA_fw)
STUB(_VerLanguageNameW_fw)
STUB(_VerQueryValueA_fw)
STUB(_VerQueryValueW_fw)

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

// Expand %app% and environment variables in a path string
static std::wstring ExpandPath(std::wstring path) {
  // Replace %app% with the directory containing the exe
  const std::wstring app_dir = GetAppDir();
  const std::wstring token = L"%app%";
  size_t pos = 0;
  while ((pos = path.find(token, pos)) != std::wstring::npos) {
    path.replace(pos, token.size(), app_dir);
    pos += app_dir.size();
  }

  // Expand environment variables like %LOCALAPPDATA%
  wchar_t expanded[MAX_PATH * 2];
  if (ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH * 2)) {
    path = expanded;
  }

  // Resolve relative paths (e.g. ..\Data)
  wchar_t full[MAX_PATH];
  if (PathCanonicalizeW(full, path.c_str())) {
    path = full;
  }
  return path;
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
  // Fallback: treat data as plaintext (portable mode)
  pDataOut->cbData = pDataIn->cbData;
  pDataOut->pbData = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, pDataOut->cbData));
  if (!pDataOut->pbData) return FALSE;
  memcpy(pDataOut->pbData, pDataIn->pbData, pDataOut->cbData);
  return TRUE;
}

// ============================================================
// Command-line injection
// ============================================================
static std::wstring BuildCommandLine(LPWSTR original_cmdline) {
  // Parse original args (skip argv[0] = exe path)
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(original_cmdline, &argc);

  std::vector<std::wstring> args;
  args.reserve(argc + 16);
  for (int i = 1; i < argc; ++i)
    args.emplace_back(argv[i]);
  if (argv) LocalFree(argv);

  // Read ini
  std::wstring data_dir_raw  = GetIniString(L"general", L"data_dir");
  std::wstring cache_dir_raw = GetIniString(L"general", L"cache_dir");
  std::wstring extra_cmdline = GetIniString(L"general", L"command_line");

  // Check if user-data-dir / disk-cache-dir already set
  bool has_user_data  = false;
  bool has_disk_cache = false;
  std::wstring combined_disable_features;

  std::vector<std::wstring> filtered;
  filtered.reserve(args.size());
  for (auto& arg : args) {
    if (arg.starts_with(L"--user-data-dir="))  { has_user_data  = true; filtered.push_back(arg); }
    else if (arg.starts_with(L"--disk-cache-dir=")) { has_disk_cache = true; filtered.push_back(arg); }
    else if (arg.starts_with(L"--disable-features=")) {
      if (!combined_disable_features.empty()) combined_disable_features += L',';
      combined_disable_features += arg.substr(wcslen(L"--disable-features="));
    }
    else { filtered.push_back(arg); }
  }
  args = std::move(filtered);

  // Parse extra command_line from ini, also merge --disable-features
  if (!extra_cmdline.empty()) {
    int eargc = 0;
    // Prepend a dummy exe name so CommandLineToArgvW parses correctly
    std::wstring fake = L"x " + extra_cmdline;
    LPWSTR* eargv = CommandLineToArgvW(fake.c_str(), &eargc);
    for (int i = 1; i < eargc; ++i) {
      std::wstring a = eargv[i];
      if (a.starts_with(L"--disable-features=")) {
        if (!combined_disable_features.empty()) combined_disable_features += L',';
        combined_disable_features += a.substr(wcslen(L"--disable-features="));
      } else {
        args.push_back(a);
      }
    }
    if (eargv) LocalFree(eargv);
  }

  // Always add WinSboxNoFakeGdiInit (required for Chromium sandbox)
  if (!combined_disable_features.empty()) combined_disable_features += L',';
  combined_disable_features += L"WinSboxNoFakeGdiInit";
  args.push_back(L"--disable-features=" + combined_disable_features);

  // Inject data/cache dirs from ini
  if (!has_user_data && !data_dir_raw.empty()) {
    std::wstring p = ExpandPath(data_dir_raw);
    if (!p.empty()) args.push_back(L"--user-data-dir=" + p);
  }
  if (!has_disk_cache && !cache_dir_raw.empty()) {
    std::wstring p = ExpandPath(cache_dir_raw);
    if (!p.empty()) args.push_back(L"--disk-cache-dir=" + p);
  }

  // Mark as portable so second-stage loader skips re-relaunching
  args.push_back(L"--portable");

  // Reassemble
  wchar_t exe_path[MAX_PATH];
  GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

  std::wstring cmdline = L"\"";
  cmdline += exe_path;
  cmdline += L"\"";
  for (auto& a : args) {
    cmdline += L' ';
    // Quote args that contain spaces
    if (a.find(L' ') != std::wstring::npos && a[0] != L'"') {
      cmdline += L'"'; cmdline += a; cmdline += L'"';
    } else {
      cmdline += a;
    }
  }
  return cmdline;
}

// ============================================================
// Entry point hook
// ============================================================
using Startup = int (*)();
static Startup ExeMain = nullptr;

static int Loader() {
  LPWSTR param = GetCommandLineW();
  // Only inject in the main browser process (not renderers/GPU/etc.)
  if (!wcsstr(param, L"-type=") && !wcsstr(param, L"--portable")) {
    std::wstring new_cmdline = BuildCommandLine(param);

    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    std::vector<wchar_t> buf(new_cmdline.begin(), new_cmdline.end());
    buf.push_back(L'\0');

    STARTUPINFOW si = { .cb = sizeof(si), .dwFlags = STARTF_USESHOWWINDOW,
                        .wShowWindow = SW_SHOWNORMAL };
    PROCESS_INFORMATION pi{};
    std::wstring app_dir = GetAppDir();
    if (CreateProcessW(exe_path, buf.data(), nullptr, nullptr, FALSE, 0,
                       nullptr, app_dir.c_str(), &si, &pi)) {
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      ExitProcess(0);
    }
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
// Forward real version.dll exports via Detours
// ============================================================
static void LoadSysDll(HINSTANCE hModule) {
  wchar_t sys_dir[MAX_PATH];
  GetSystemDirectoryW(sys_dir, MAX_PATH);
  std::wstring dll_path = std::wstring(sys_dir) + L"\\version.dll";
  HINSTANCE real = LoadLibraryW(dll_path.c_str());
  if (!real) return;

  // For each stub, detour it to the real function
  auto hook = [&](const char* name, LPVOID* stub_ptr) {
    auto real_fn = reinterpret_cast<PBYTE>(GetProcAddress(real, name));
    if (!real_fn) return;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(stub_ptr, real_fn);
    DetourTransactionCommit();
  };

#define HOOK_VERSION(name) \
  { auto p = reinterpret_cast<LPVOID>(name##_fw); hook(#name, &p); }

  // Hook each export stub to real version.dll
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
    auto fn_name = reinterpret_cast<char*>(image_base + names[i]);
    auto real_fn = reinterpret_cast<PBYTE>(GetProcAddress(real, fn_name));
    if (!real_fn) continue;
    auto stub = reinterpret_cast<PBYTE>(image_base + funcs[ordinals[i]]);
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

    // Hook Crypt* for portable profile
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptProtectData),
                 reinterpret_cast<void*>(MyCryptProtectData));
    DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptUnprotectData),
                 reinterpret_cast<void*>(MyCryptUnprotectData));
    DetourTransactionCommit();

    InstallLoader();
  }
  return TRUE;
}
