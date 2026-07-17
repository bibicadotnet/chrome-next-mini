#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <propkey.h>
#include <shobjidl.h>
#include <intrin.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <ranges>
#include <span>
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
// FakeGetComputerName / FakeGetVolumeInformation
// Prevent profile from binding to a specific machine or drive
// https://source.chromium.org/chromium/chromium/src/+/main:rlz/win/lib/machine_id_win.cc;l=41
// ============================================================
static auto RawGetVolumeInformationW = GetVolumeInformationW;
static auto RawGetComputerNameW      = GetComputerNameW;

static BOOL WINAPI FakeGetComputerName(LPTSTR, LPDWORD) {
  return FALSE;
}

static BOOL WINAPI FakeGetVolumeInformation(
    LPCTSTR lpRootPathName, LPTSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags, LPTSTR lpFileSystemNameBuffer,
    DWORD nFileSystemNameSize) {
  if (lpVolumeSerialNumber != nullptr)
    return FALSE;
  return RawGetVolumeInformationW(
      lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
      lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags,
      lpFileSystemNameBuffer, nFileSystemNameSize);
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
    if (GetPrivateProfileIntW(L"general", L"win32k", 0, GetIniPath().c_str()))
      policy[0] &= ~kWin32kSystemCallDisableAlwaysOn;
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
// MakeGreen — bundles FakeGetComputerName, FakeGetVolumeInformation,
// MyUpdateProcThreadAttribute, MyCryptProtectData, MyCryptUnprotectData.
//
// Mirrors chrome_plus's green.cc MakeGreen(): this must only ever be
// called for the main browser process (see Loader() below), never
// unconditionally from DllMain. Attaching these hooks in every process
// image loads version.dll into (renderer, GPU, utility, crashpad-handler,
// ...) is NOT what the upstream project does and must be avoided —
// MyUpdateProcThreadAttribute in particular affects every child process
// spawn made by whichever process it runs in, so it must stay scoped to
// the single browser process that actually spawns children on behalf of
// the user.
// ============================================================
static void MakeGreen() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<LPVOID*>(&RawGetComputerNameW),
               reinterpret_cast<void*>(FakeGetComputerName));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawGetVolumeInformationW),
               reinterpret_cast<void*>(FakeGetVolumeInformation));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawUpdateProcThreadAttribute),
               reinterpret_cast<void*>(MyUpdateProcThreadAttribute));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptProtectData),
               reinterpret_cast<void*>(MyCryptProtectData));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawCryptUnprotectData),
               reinterpret_cast<void*>(MyCryptUnprotectData));
  DetourTransactionCommit();
}

// ============================================================
// AppId — unique AppUserModelID per install directory
// Prevents multiple portable instances from merging in taskbar
// ============================================================
static uint64_t Fnv1aHash(std::wstring_view input) {
  uint64_t hash = 14695981039346656037ULL;
  auto bytes = std::as_bytes(std::span{input});
  for (auto b : bytes) {
    hash ^= static_cast<uint64_t>(b);
    hash *= 1099511628211ULL;
  }
  return hash;
}

static const std::wstring& GetCustomAppUserModelID() {
  static const std::wstring custom_appid = [] {
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    auto hash = Fnv1aHash(GetAppDir());
    std::wstring result{L"BrowserPortable."};
    result.reserve(result.size() + 16);
    for (int i = 60; i >= 0; i -= 4)
      result += hex[(hash >> i) & 0xF];
    return result;
  }();
  return custom_appid;
}

static bool IsBrowserWindow(HWND hwnd) {
  wchar_t cls[256];
  GetClassNameW(hwnd, cls, 256);
  return wcsncmp(cls, L"Chrome_WidgetWin_", 17) == 0;
}

struct PropVariantDeleter {
  void operator()(PROPVARIANT* pv) const { PropVariantClear(pv); delete pv; }
};
using ScopedPropVariant = std::unique_ptr<PROPVARIANT, PropVariantDeleter>;

static ScopedPropVariant MakeAppIdVariant() {
  auto pv = ScopedPropVariant(new PROPVARIANT{});
  pv->vt = VT_EMPTY;
  const auto& id = GetCustomAppUserModelID();
  const size_t char_count = id.size() + 1;
  const size_t byte_len = char_count * sizeof(wchar_t);
  pv->pwszVal = static_cast<LPWSTR>(CoTaskMemAlloc(byte_len));
  if (pv->pwszVal) {
    pv->vt = VT_LPWSTR;
    std::span<wchar_t> dest{pv->pwszVal, char_count};
    auto result = std::ranges::copy(id, dest.begin());
    *result.out = L'\0';
  }
  return pv;
}

class PropertyStoreWrapper final : public IPropertyStore {
 public:
  explicit PropertyStoreWrapper(IPropertyStore* real) : real_(real) {}
  ~PropertyStoreWrapper() { if (real_) real_->Release(); }
  PropertyStoreWrapper(const PropertyStoreWrapper&) = delete;
  PropertyStoreWrapper& operator=(const PropertyStoreWrapper&) = delete;

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IPropertyStore) {
      *ppv = static_cast<IPropertyStore*>(this);
      AddRef();
      return S_OK;
    }
    return real_->QueryInterface(riid, ppv);
  }
  ULONG STDMETHODCALLTYPE AddRef() override {
    return ref_.fetch_add(1, std::memory_order_relaxed) + 1;
  }
  ULONG STDMETHODCALLTYPE Release() override {
    auto c = ref_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (c == 0) delete this;
    return c;
  }
  HRESULT STDMETHODCALLTYPE GetCount(DWORD* c) override { return real_->GetCount(c); }
  HRESULT STDMETHODCALLTYPE GetAt(DWORD i, PROPERTYKEY* k) override { return real_->GetAt(i, k); }
  HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY key, PROPVARIANT* pv) override {
    if (IsEqualPropertyKey(key, PKEY_AppUserModel_ID)) {
      auto v = MakeAppIdVariant();
      *pv = *v; v->vt = VT_EMPTY;
      return S_OK;
    }
    return real_->GetValue(key, pv);
  }
  HRESULT STDMETHODCALLTYPE SetValue(REFPROPERTYKEY key, REFPROPVARIANT propvar) override {
    if (IsEqualPropertyKey(key, PKEY_AppUserModel_ID)) {
      auto v = MakeAppIdVariant();
      return real_->SetValue(key, *v);
    }
    return real_->SetValue(key, propvar);
  }
  HRESULT STDMETHODCALLTYPE Commit() override { return real_->Commit(); }

 private:
  IPropertyStore* real_;
  std::atomic<ULONG> ref_{1};
};

static auto RawSetCurrentProcessExplicitAppUserModelID =
    SetCurrentProcessExplicitAppUserModelID;

static HRESULT WINAPI MySetCurrentProcessExplicitAppUserModelID(PCWSTR) {
  return RawSetCurrentProcessExplicitAppUserModelID(
      GetCustomAppUserModelID().c_str());
}

static auto RawSHGetPropertyStoreForWindow = SHGetPropertyStoreForWindow;

static HRESULT WINAPI MySHGetPropertyStoreForWindow(HWND hwnd, REFIID riid,
                                                     void** ppv) {
  HRESULT hr = RawSHGetPropertyStoreForWindow(hwnd, riid, ppv);
  if (SUCCEEDED(hr) && ppv && *ppv && riid == IID_IPropertyStore) {
    if (IsBrowserWindow(hwnd)) {
      auto* wrapper = new (std::nothrow)
          PropertyStoreWrapper(static_cast<IPropertyStore*>(*ppv));
      if (wrapper) *ppv = static_cast<IPropertyStore*>(wrapper);
    }
  }
  return hr;
}

static void SetAppId() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(
      reinterpret_cast<LPVOID*>(&RawSetCurrentProcessExplicitAppUserModelID),
      reinterpret_cast<void*>(MySetCurrentProcessExplicitAppUserModelID));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawSHGetPropertyStoreForWindow),
               reinterpret_cast<void*>(MySHGetPropertyStoreForWindow));
  DetourTransactionCommit();
}

// ============================================================
// Policies — ignore enterprise registry policies
// ============================================================
static auto RawRegOpenKeyExW = RegOpenKeyExW;

static bool IsPolicyKey(LPCWSTR lpSubKey) {
  if (!lpSubKey) return false;
  return StrStrIW(lpSubKey, L"Policies\\Google\\Chrome") ||
         StrStrIW(lpSubKey, L"Policies\\Microsoft\\Edge") ||
         StrStrIW(lpSubKey, L"Policies\\Chromium") ||
         StrStrIW(lpSubKey, L"Policies\\BraveSoftware\\Brave") ||
         StrStrIW(lpSubKey, L"Policies\\CocCoc");
}

// ============================================================
// SuppressFalseUpgradeNotification helpers
// ============================================================
// Read the running Chrome version from chrome.dll's embedded VS_FIXEDFILEINFO.
// Used to spoof the "pv" registry value so Chrome's InstalledVersionPoller
// sees installed == running and clears the false "out of date" prompt.
static std::wstring ComputeRunningChromeVersion() {
  HMODULE chrome_dll = GetModuleHandleW(L"chrome.dll");
  if (!chrome_dll) return {};
  HRSRC resource = FindResourceW(chrome_dll, MAKEINTRESOURCEW(VS_VERSION_INFO),
                                 RT_VERSION);
  if (!resource) return {};
  const DWORD resource_size = SizeofResource(chrome_dll, resource);
  HGLOBAL loaded = LoadResource(chrome_dll, resource);
  const auto* data =
      loaded ? static_cast<const BYTE*>(LockResource(loaded)) : nullptr;
  if (!data || resource_size < sizeof(VS_FIXEDFILEINFO)) return {};
  for (DWORD offset = 0;
       offset + sizeof(VS_FIXEDFILEINFO) <= resource_size;
       offset += sizeof(DWORD)) {
    const auto* info =
        reinterpret_cast<const VS_FIXEDFILEINFO*>(data + offset);
    if (info->dwSignature != 0xFEEF04BD) continue;
    if (info->dwFileVersionMS == 0 && info->dwFileVersionLS == 0) return {};
    return std::to_wstring(HIWORD(info->dwFileVersionMS)) + L'.' +
           std::to_wstring(LOWORD(info->dwFileVersionMS)) + L'.' +
           std::to_wstring(HIWORD(info->dwFileVersionLS)) + L'.' +
           std::to_wstring(LOWORD(info->dwFileVersionLS));
  }
  return {};
}

static std::wstring RunningChromeVersion() {
  static std::wstring cached;
  if (cached.empty()) cached = ComputeRunningChromeVersion();
  return cached;
}

// Vendor policy path prefixes we intercept.
static const wchar_t* const kPolicyPatterns[] = {
    L"Policies\\Google\\Chrome",
    L"Policies\\Microsoft\\Edge",
    L"Policies\\Chromium",
    L"Policies\\BraveSoftware\\Brave",
    L"Policies\\CocCoc",
};

// Reads general.policy_key from chrome++.ini. When non-empty, policy
// registry reads for THIS portable instance are redirected from the shared
// vendor key (e.g. Policies\Microsoft\Edge) to an isolated sibling key
// (e.g. Policies\Microsoft\Edge_<policy_key>). This lets multiple portable
// installs (different Edge/Chrome versions) each point at their own
// private set of "regedit" policies without colliding on the one shared
// key Windows normally uses.
static std::wstring GetPolicyKeySuffix() {
  return GetIniString(L"general", L"policy_key");
}

// Rewrites lpSubKey so the matched vendor policy pattern gets `_<suffix>`
// appended right after it, preserving anything that follows (e.g.
// "...\Edge\Recommended" -> "...\Edge_v139\Recommended").
static std::wstring RedirectPolicySubKey(LPCWSTR lpSubKey,
                                          const std::wstring& suffix) {
  std::wstring sub(lpSubKey ? lpSubKey : L"");
  for (const wchar_t* pattern : kPolicyPatterns) {
    LPCWSTR found = StrStrIW(sub.c_str(), pattern);
    if (!found) continue;
    const size_t pos = found - sub.c_str();
    const size_t pattern_len = wcslen(pattern);
    return sub.substr(0, pos + pattern_len) + L"_" + suffix +
           sub.substr(pos + pattern_len);
  }
  return sub;
}

static LSTATUS APIENTRY MyRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey,
                                         DWORD ulOptions, REGSAM samDesired,
                                         PHKEY phkResult) {
  if ((hKey == HKEY_LOCAL_MACHINE || hKey == HKEY_CURRENT_USER) &&
      IsPolicyKey(lpSubKey)) {
    if (GetIniString(L"general", L"ignore_policies") == L"1")
      return ERROR_FILE_NOT_FOUND;

    const std::wstring suffix = GetPolicyKeySuffix();
    if (!suffix.empty()) {
      const std::wstring redirected = RedirectPolicySubKey(lpSubKey, suffix);
      return RawRegOpenKeyExW(hKey, redirected.c_str(), ulOptions,
                               samDesired, phkResult);
    }
  }
  return RawRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

static auto RawRegQueryValueExW = RegQueryValueExW;

// Intercept "pv" reads and return the running Chrome version so that
// InstalledVersionPoller computes installed == running → no false prompt.
static LSTATUS APIENTRY MyRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName,
                                            LPDWORD lpReserved, LPDWORD lpType,
                                            LPBYTE lpData, LPDWORD lpcbData) {
  if (lpValueName && lstrcmpiW(lpValueName, L"pv") == 0) {
    const std::wstring version = RunningChromeVersion();
    if (!version.empty()) {
      const DWORD size =
          static_cast<DWORD>((version.size() + 1) * sizeof(wchar_t));
      if (lpType) *lpType = REG_SZ;
      if (!lpData) {
        if (lpcbData) *lpcbData = size;
        return ERROR_SUCCESS;
      }
      if (lpcbData) {
        if (*lpcbData < size) { *lpcbData = size; return ERROR_MORE_DATA; }
        std::memcpy(lpData, version.c_str(), size);
        *lpcbData = size;
        return ERROR_SUCCESS;
      }
    }
  }
  return RawRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData,
                              lpcbData);
}

// Separate raw pointer so this hook is fully independent of IgnorePolicies.
static auto RawRegOpenKeyExW_Upgrade = RegOpenKeyExW;

static LSTATUS APIENTRY MyRegOpenKeyExW_Upgrade(HKEY hKey, LPCWSTR lpSubKey,
                                                 DWORD ulOptions,
                                                 REGSAM samDesired,
                                                 PHKEY phkResult) {
  const LSTATUS result =
      RawRegOpenKeyExW_Upgrade(hKey, lpSubKey, ulOptions, samDesired, phkResult);
  if (result != ERROR_SUCCESS && phkResult && lpSubKey &&
      StrStrIW(lpSubKey, L"Google\\Update\\Clients\\")) {
    if (RawRegOpenKeyExW_Upgrade(hKey, L"", 0, samDesired, phkResult) ==
        ERROR_SUCCESS) {
      return ERROR_SUCCESS;
    }
    // Fallback also failed: fall through and return the original error
    // instead of reporting success with an invalid phkResult.
  }
  return result;
}

static void IgnorePolicies() {
  const bool ignore = GetIniString(L"general", L"ignore_policies") == L"1";
  const bool redirect = !GetPolicyKeySuffix().empty();
  if (!ignore && !redirect) return;
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<LPVOID*>(&RawRegOpenKeyExW),
               reinterpret_cast<void*>(MyRegOpenKeyExW));
  DetourTransactionCommit();
}

static void SuppressFalseUpgradeNotification() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourAttach(reinterpret_cast<LPVOID*>(&RawRegOpenKeyExW_Upgrade),
               reinterpret_cast<void*>(MyRegOpenKeyExW_Upgrade));
  DetourAttach(reinterpret_cast<LPVOID*>(&RawRegQueryValueExW),
               reinterpret_cast<void*>(MyRegQueryValueExW));
  DetourTransactionCommit();
}

// ============================================================
// Command-line builder — mirrors portable.cc logic
// ============================================================
static bool IsWhitespaceChar(wchar_t ch) {
  return ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\r';
}

// Finds `flag` as a whole "word" in `command_line` (bounded by whitespace or
// string edges), so "--foo" doesn't spuriously match inside "--foobar".
static size_t FindStandaloneSwitch(std::wstring_view command_line,
                                    std::wstring_view flag) {
  size_t pos = command_line.find(flag);
  while (pos != std::wstring_view::npos) {
    const bool at_start = pos == 0 || IsWhitespaceChar(command_line[pos - 1]);
    const size_t after = pos + flag.size();
    const bool at_end =
        after >= command_line.size() || IsWhitespaceChar(command_line[after]);
    if (at_start && at_end) return pos;
    pos = command_line.find(flag, pos + flag.size());
  }
  return std::wstring_view::npos;
}

static void TrimTrailingWhitespace(std::wstring& text) {
  while (!text.empty() && IsWhitespaceChar(text.back())) text.pop_back();
}

// The `--single-argument` switch is used by the Windows Shell for file
// associations. CommandLineToArgvW can mis-split the argument that follows
// it (typically a file path with spaces), so split it out here: the part
// before the switch gets parsed/modified as usual, while the switch and its
// entire trailing argument are appended verbatim at the very end. Mirrors
// portable.cc's SplitSingleArgumentSwitch (fix for chrome_plus issue #181).
static std::pair<std::wstring, std::wstring> SplitSingleArgumentSwitch(
    const std::wstring& command_line) {
  constexpr std::wstring_view kSingleArgument = L"--single-argument";
  const size_t pos = FindStandaloneSwitch(command_line, kSingleArgument);
  if (pos == std::wstring_view::npos) return {command_line, L""};

  std::wstring prefix = command_line.substr(0, pos);
  std::wstring suffix = command_line.substr(pos);
  TrimTrailingWhitespace(prefix);
  return {std::move(prefix), std::move(suffix)};
}

// Separates arguments before and after a lone "--" sentinel. Everything
// after it is positional (e.g. a URL) and must be preserved verbatim at the
// end of the final command line, not merged with --disable-features / etc.
// Mirrors portable.cc's SeparateSentinelArgs.
static std::pair<std::vector<std::wstring>, std::vector<std::wstring>>
SeparateSentinelArgs(std::vector<std::wstring> args) {
  size_t sentinel = args.size();
  for (size_t i = 0; i < args.size(); ++i) {
    if (args[i] == L"--") { sentinel = i; break; }
  }
  if (sentinel == args.size()) return {std::move(args), {}};

  std::vector<std::wstring> trailing(args.begin() + sentinel, args.end());
  args.erase(args.begin() + sentinel, args.end());
  return {std::move(args), std::move(trailing)};
}

static std::wstring GetCommand(LPWSTR param) {
  // Split off any "--single-argument <path>" tail before touching the rest.
  auto [command_line, single_arg_suffix] =
      SplitSingleArgumentSwitch(param ? param : L"");

  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(command_line.c_str(), &argc);

  std::vector<std::wstring> raw_args;
  raw_args.reserve(argc + 16);
  // skip argv[0] (exe path)
  for (int i = 1; i < argc; ++i)
    raw_args.emplace_back(argv[i]);
  if (argv) LocalFree(argv);

  // Split off anything after a lone "--" sentinel; it must stay positional
  // and untouched at the end of the final command line.
  auto [args, trailing_args] = SeparateSentinelArgs(std::move(raw_args));

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

  // Merge --disable-features and --enable-features each into one
  std::wstring combined_disable;
  std::wstring combined_enable;
  std::vector<std::wstring> final_args;
  final_args.reserve(args.size() + trailing_args.size() + 4);
  bool has_user_data  = false;
  bool has_disk_cache = false;

  for (auto& arg : args) {
    if (arg.starts_with(L"--disable-features=")) {
      if (!combined_disable.empty()) combined_disable += L',';
      combined_disable += arg.substr(wcslen(L"--disable-features="));
    } else if (arg.starts_with(L"--enable-features=")) {
      if (!combined_enable.empty()) combined_enable += L',';
      combined_enable += arg.substr(wcslen(L"--enable-features="));
    } else {
      if (arg.starts_with(L"--user-data-dir="))  has_user_data  = true;
      if (arg.starts_with(L"--disk-cache-dir=")) has_disk_cache = true;
      final_args.push_back(arg);
    }
  }

  // OutdatedBuildDetector is disabled by default here (unlike upstream
  // chrome_plus, which leaves it enabled) so the "build is outdated, please
  // relaunch" prompt never shows on portable installs that can't
  // self-update — intentional for this fork, not a bug.
  if (!combined_disable.empty()) combined_disable += L',';
  combined_disable += L"OutdatedBuildDetector,WinSboxNoFakeGdiInit";
  final_args.emplace_back(L"--disable-features=" + combined_disable);

  if (!combined_enable.empty())
    final_args.emplace_back(L"--enable-features=" + combined_enable);

  if (!has_user_data) {
    std::wstring d = GetIniString(L"general", L"data_dir");
    if (!d.empty()) final_args.emplace_back(L"--user-data-dir=" + ExpandPath(d));
  }
  if (!has_disk_cache) {
    std::wstring c = GetIniString(L"general", L"cache_dir");
    if (!c.empty()) final_args.emplace_back(L"--disk-cache-dir=" + ExpandPath(c));
  }

  // Re-attach the "--" sentinel and anything positional after it, verbatim.
  for (auto& t : trailing_args) final_args.push_back(std::move(t));

  std::wstring result;
  for (auto& a : final_args) {
    if (!result.empty()) result += L' ';
    result += QuoteIfNeeded(a);
  }

  // Re-attach the "--single-argument <path>" tail, verbatim, at the very end.
  if (!single_arg_suffix.empty()) {
    if (!result.empty()) result += L' ';
    result += single_arg_suffix;
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
    // Second launch (--portable present): run normally.
    // This is the ChromePlus()-equivalent path — everything here runs
    // exactly once, in the main browser process only, never in a
    // renderer/GPU/utility/crashpad-handler process.
    SetAppId();
    MakeGreen();
    IgnorePolicies();
    SuppressFalseUpgradeNotification();
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

    // Maintain the original function of version.dll. This runs in every
    // process the DLL is loaded into (browser, renderer, GPU, utility,
    // crashpad-handler, ...) because every one of them still needs the
    // real GetFileVersionInfo*/Ver* exports to keep working — same as
    // chrome++.cc's DllMain.
    LoadSysDll(hModule);

    // Detour the exe's entry point. The actual hook set (MakeGreen,
    // SetAppId, IgnorePolicies, SuppressFalseUpgradeNotification) is
    // decided later, inside Loader(), once the command line can be
    // inspected for "-type=" / "--portable" — exactly mirroring
    // chrome++.cc's InstallLoader()/Loader()/ChromePlusCommand() split.
    // No hook other than the entry-point detour and the version.dll
    // passthrough may be attached unconditionally here.
    InstallLoader();
  }
  return TRUE;
}
