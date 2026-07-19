# IL2CPP Lens (iOS)

Đây là project iOS thật, không phải script Python. App SwiftUI nhận diện theo chữ ký nội dung nên không bắt buộc file phải có tên `global-metadata.dat`: có thể chọn metadata đổi tên, Mach-O, `.app`, `.ipa`, `.zip`, hoặc file nhị phân bất kỳ.

## Build bằng GitHub Actions

1. Tạo repo mới trên GitHub và upload toàn bộ thư mục này.
2. Vào **Actions → Build unsigned IPA → Run workflow** (hoặc push vào `main`/`master`).
3. Tải artifact `IL2CPPLens-unsigned-ipa` ở cuối workflow.

Workflow dùng macOS runner, cài XcodeGen, tạo `.xcodeproj`, build `iphoneos`, rồi đóng `.app` thành `.ipa`.

IPA mặc định là **unsigned** vì repo không nên chứa certificate/provisioning profile. Nó phù hợp để kiểm tra artifact hoặc ký lại bằng công cụ sideload. Muốn cài trực tiếp lên iPhone bình thường, cần thêm signing secrets và bước `xcodebuild -exportArchive` theo Team ID/provisioning profile của bạn.

## App hiện có gì

- File picker không giới hạn tên file.
- Quét IPA/ZIP và các entry bên trong.
- Nhận diện IL2CPP metadata magic `0xFAB11BAF`, đọc version/header và các layout phổ biến v27–v31.
- Hiển thị type, field, method theo dạng `Namespace.Type.field : metadata+0xOFFSET : token`.
- Nhận diện thin/fat Mach-O, CPU, load-command area và `__TEXT` base cơ bản.
- Tìm kiếm tên symbol trong kết quả.

Offset được gắn nhãn **metadata-relative**; nó không tự động là địa chỉ runtime hay patch value. Bản đầu tiên cố ý chỉ đọc để tránh làm hỏng file gốc. Có thể thêm patch/compare lab sau khi xác nhận parser trên các dump thật của bạn.

## Mở local bằng Xcode

Trên máy Mac có XcodeGen:

```sh
brew install xcodegen
xcodegen generate
open IL2CPPLens.xcodeproj
```

Dependency ZIPFoundation được khai báo bằng Swift Package Manager để đọc IPA/ZIP trong app.
