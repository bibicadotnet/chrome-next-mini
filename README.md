
# Chrome++ Next Mini

Phiên bản tối giản, dùng các logic có sẵn từ [Chrome++ Next](https://github.com/Bush2021/chrome_plus)

- Chỉ giữ lại tính năng Portable, loại bỏ phần lớn tính năng nâng cao của bản gốc Chrome++
  
Phiên bản ổn định hiện tại v1.0.7, gần như không cần bảo trì, trừ khi lõi Chromium thay đổi hoàn toàn cấu trúc

### Cài đặt và sử dụng
Download edge_portable-*.zip tại release, giải nén

- Trên Chromium/Chrome/Helium/Thorium/Cốc Cốc ... chép 2 file `chrome++.ini` và `version.dll` trong cùng thư mục với `chrome.exe`
- Trên Edge, chép 3 file `chrome++.ini`, `setdll-x64.exe`, `version.dll` trong cùng thư mục với `msedge.exe`, sau đó gọi PowerShell, chạy lệnh `./setdll-x64.exe /d:version.dll msedge.exe`

Phương pháp patch để chạy ở chế độ di động, Microsoft Defender Antivirus đôi khi có thể nhận diện nhầm nó là một phần mềm độc hại / trojan / visrus  (thường sau 3-7 ngày, khi Microsoft cập nhập dữ liệu, sẽ hết cảnh báo)

### Cấu hình 

- Tạo file cấu hình `chrome++.ini` đơn giản nhất có thể
```
[general]
data_dir=%app%\..\Data
cache_dir=%app%\..\Cache
command_line=
ignore_policies=0
win32k=0
policy_key=Portable
```

Giải thích chi tiết các cấu hình:

- `ignore_policies` giữ lại, phòng tình huống bạn cần 1 bản portable tách rời hoàn toàn với các cấu hình regedit (`ignore_policies=1` sẽ không dùng các cấu hình trong regedit)
- `win32k` giữ lại vì không chắc Chromium gặp sự cố nào khi khởi động không (nếu bật trình duyệt, thấy crash ngay, đổi sang `win32k=1`)
- `policy_key=Portable`: đây là tính năng mới được thêm vào cho Chrome++ Next Mini. Tác dụng của nó là điều hướng trình duyệt đọc cấu hình Registry ở một nhánh riêng biệt, không sử dụng chung nhánh mặc định của hệ thống.
  - Lấy ví dụ, trước đây trên trình duyệt Edge, mặc định cả bản cài đặt (Default) và bản Portable đều dùng chung một nhánh Registry là `[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge]`
  - Tình huống xảy ra khi bạn muốn chạy song song nhiều bản Edge (cả bản cài đặt gốc lẫn bản Portable), hoặc dùng nhiều phiên bản Portable khác nhau (v110, v138, v150...), việc dùng chung một nhánh Registry sẽ gây xung đột hoặc lỗi policy. `policy_key` giúp mỗi bản Portable trỏ tới cấu hình riêng để tùy chỉnh độc lập, giải quyết tình trạng đụng độ này.
  - Khi cấu hình `policy_key=Portable` trong file `chrome++.ini`, bản Edge Portable đó thay vì đọc ở nhánh gốc sẽ tự động chuyển hướng sang nhánh mới là `[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge_Portable]`. Tương tự, nếu bạn đặt `policy_key=v138`, nhánh Registry sẽ trở thành `[...\Edge_v138]`.
 
Ví dụ cấu hình hoàn chỉnh trên Cốc Cốc
```
[general]
data_dir=%app%\..\Data
cache_dir=%app%\..\Cache
command_line=--no-first-run --no-default-browser-check --disable-features=CocCocAskAi,ExtensionManifestV2Unsupported,ExtensionManifestV2Disabled
win32k=0
ignore_policies=0
policy_key=Portable
```

Trên Edge, nên tắt tính năng `App-Bound Encryption` qua regedit cho an toàn 

```
Windows Registry Editor Version 5.00

; Phục hồi về mặc định
[-HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Edge_Portable]
; Cấu hình cài đặt
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge]
"ApplicationBoundEncryptionEnabled"=dword:00000000
```
