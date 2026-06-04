
# Chrome++ Next Mini (thử nghiệm)

Phiên bản tối giản của [Chrome++ Next](https://github.com/Bush2021/chrome_plus), không hẳn là bản fork, cũng không hẳn là viết mới, vì dùng lại logic có sẵn từ Chrome++ Next

- Cấu hình `chrome++.ini` đơn giản nhất có thể
```
[general]
data_dir=%app%\..\Data
cache_dir=%app%\..\Cache
command_line=--no-first-run --no-default-browser-check --disable-features=ExtensionManifestV2Unsupported,ExtensionManifestV2Disabled,OmniboxContextualSearchOnFocusSuggestions,OmniboxContextualSuggestions
ignore_policies=0
win32k=0
```

Beta test, không chắc Edge khi chạy 1 thời gian có bị lỗi như bản Chrome++ Next gốc không, nghi ngờ khả năng chạy mặc định `App-Bound Encryption` có thể tạo ra tình huống crash ngẫu nhiên, đợt thử nghiệm này tắt đi xem thế nào

```
Windows Registry Editor Version 5.00

; Phục hồi về mặc định
[-HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate]
[-HKEY_CURRENT_USER\Software\Policies\Microsoft\Edge]
[-HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\EdgeUpdate]

; Cấu hình cài đặt
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge]

"ApplicationBoundEncryptionEnabled"=dword:00000000
```
