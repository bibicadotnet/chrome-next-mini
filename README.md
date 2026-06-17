
# Chrome++ Next Mini (thử nghiệm)

Phiên bản tối giản của [Chrome++ Next](https://github.com/Bush2021/chrome_plus), không hẳn là bản fork, cũng không hẳn là viết mới, vì dùng lại logic có sẵn từ Chrome++ Next

### Cài đặt
Download edge_portable-*.zip tại release, giải nén

- Trên Chromium/Chrome/Cốc Cốc ... chép 2 file `chrome++.ini` và `version.dll` trong cùng thư mục với `chrome.exe`
- Trên Edge, chép 3 file `chrome++.ini`, `setdll-x64.exe`, `version.dll` trong cùng thư mục với `msedge.exe`, sau đó gọi PowerShell, chạy lệnh `./setdll-x64.exe /d:version.dll msedge.exe`

Do phương pháp patch để chạy ở chế độ di động, Microsoft Defender Antivirus đôi khi có thể nhận diện nhầm nó là một phần mềm độc hại / trojan / visrus  (thường sau 3-7 ngày, khi Microsoft cập nhập dữ liệu, sẽ hết cảnh báo)

Bản Chrome++ Next Mini hiện tại vẫn chưa thấy bị cảnh báo nhầm

### Cấu hình 
Tất cả tính năng nâng cao của bản gốc Chrome++ bỏ hết (vì không biết tính năng nào tạo ra lỗi ở Edge)

- Cấu hình `chrome++.ini` đơn giản nhất có thể
```
[general]
data_dir=%app%\..\Data
cache_dir=%app%\..\Cache
command_line=
ignore_policies=0
win32k=0
```
- 2 tính năng ignore_policies và win32k mặc định tắt
- ignore_policies giữ lại, phòng tình huống bạn cần 1 bản portable tách rời hoàn toàn với các cấu hình regedit (`ignore_policies=1` sẽ không dùng các cấu hình trong regedit)
- win32k giữ lại vì không chắc Chromium gặp sự cố nào khi khởi động không (nếu bật trình duyệt, thấy crash ngay, đổi sang `win32k=1`)

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
