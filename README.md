## Antidebug challs

### anti1.exe

Bài này về mặt debug, chỉ cần đặt bp ở dòng call IsDebbugPresent là debug được

Hơn nữa, cách viết mã của bài này khá lộ, không cần debug cũng giải ra được

Cơ chế hoạt động:
  - Nhìn vào graph view ta thấy được 2 thứ:

<img width="241" height="684" alt="ida_rz0UXnEdbO" src="https://github.com/user-attachments/assets/773ef141-4adc-48ea-9078-438df31ecdd4" />

<img width="479" height="308" alt="ida_Xmi45Xa2DQ" src="https://github.com/user-attachments/assets/8eeac265-b69f-4638-8eb8-0347d671717a" />

  - Và cái hàm có chuỗi BKSEECCCC!! đang gọi cái loc ở ảnh bên trên
  - Vị vậy ta hiểu được hàm dưới này đang sử dụng loc_401AD5 cho mục đích nào đó
  - Thấy loc_401307 gọi sub_401220, ta xem thử sub_401220 và thấy
<img width="535" height="286" alt="ida_hgrRnwTheA" src="https://github.com/user-attachments/assets/a62be077-579d-406c-9689-686c9c4f3926" />
  - Thì những gì hàm này làm là:
      - Lấy độ dài key
      - Cho nó đi qua vòng lặp 53 bước (vì số lượng kí tự cần xử lý kia là 53)
      - Lấy kí tự ở vị trí (vị trí hiện tại (gọi là i) chia lấy dư cho số kí tự của key)
      - Xor kí tự đấy với kí tự của key ở vị trí i
- Code giải:
```
data = [0x00, 0x00, 0x00, 0x00, 0x06, 0x38, 0x26, 0x77, 0x30, 0x58, 0x7E, 0x42, 0x2A, 0x7F, 0x3F, 0x29, 0x1A, 0x21, 0x36, 0x37, 0x1C, 0x55, 0x49, 0x12, 0x30, 0x78, 0x0C, 0x28, 0x30, 0x30, 0x37, 0x1C, 0x21, 0x12, 0x7E, 0x52, 0x2D, 0x26, 0x60, 0x1A, 0x24, 0x2D, 0x37, 0x72, 0x1C, 0x45, 0x44, 0x43, 0x37, 0x2C, 0x6C, 0x7A, 0x38]
key = "BKSEECCCC!!!"
flag = "".join(chr(data[i] ^ ord(key[i % len(key)])) for i in range(len(data)))
print("Flag:", flag)
```

Ta ra được flag là BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}

### Replace.exe

Đọc hàm main, ta thấy được:

<img width="599" height="752" alt="Photoshop_Jyje5UzVit" src="https://github.com/user-attachments/assets/2e070b83-9301-43d2-ba4d-f5811e9c10ee" />

  - Biến v12 có giá trị là xâu VdlKe9upfBFkkO0L
  - Buffer qua lệnh fgets có thể là đoạn kí tự người dùng nhập vào
  - Biến v10 xác định độ dài chuỗi nhập vào (v10 = strlen(Buffer);)
  - Kiểm tra xem độ dài này chia 8 được không (if ( v10 % 8 )) (thông thường những bài ctf thì flag sẽ có độ dài dưới 40 kí tự, vậy có thể flag này có độ dài 32 hoặc 40 kí tự)
  - Biến Buf2 lấy dữ liệu từ unk_40315C, là một chuỗi byte 
  - Hàm sub_401180 sử dụng tới 2 biến v12 và Buffer

Đọc hàm sub_401180, ta thấy quá trình mã hóa như sau:
  - a1 là chuỗi người dùng nhập vào
  - a2 là biến v12
  - 2 điều này có được thông qua lệnh gọi hàm: sub_401180(Buffer, v12);
  - Kí tự đầu tiên của a1 được xor với tổng 2 phần tử đầu của a2 (qua câu lệnh *a1 ^= a2[1] + *a2;)
  - Kí tự thứ 2 của a1 được xor với tổng 2 phần tử thứ 3 và 4 của a2

Kiểm tra dữ liệu từ unc_40315C trong ida, bỏ qua mấy byte 0 ở cuối ta được chuỗi byte sau

<img width="1533" height="741" alt="ida_8RbJL4enpS" src="https://github.com/user-attachments/assets/43b6839f-9ae3-4352-bc18-8c6d26e4aa5c" />

Từ đó, ta biết flag có 48 kí tự

Ngoài ra ở hàm sub_401180 ta thấy hàm sử dụng 4 phần tử của v12, mà biến v12 là xâu gồm 16 kí tự, vậy thì biến này đã được chẻ làm 4 để phục vụ cho việc mã hóa

Còn biến Buffer có lẽ được chẻ đôi

Thử viết ngược lại chương trình theo logic này nhưng không thu được kết quả

<img width="1089" height="1023" alt="gBfLTY5e8c" src="https://github.com/user-attachments/assets/88c2e9bb-6d1c-4e16-b88b-678da830583c" />

Có vẻ là đoạn code này sử dụng kiểu mã hóa TEA (Tiny Encryption Algorithm), sau mỗi lần xor, đầu ra được thêm vào 0x9E3779B9

Mã giải chương trình:
```
import struct

def decrypt_tea(v, k):
    """
    Giải mã một khối 8-byte (v) bằng khóa 16-byte (k).
    v: đoạn 8 byte chia làm đôi v0 và v1
    k: key chia thành 4 phần k1 k2 k3 k4
    """
    v0, v1 = v
    k0, k1, k2, k3 = k
    delta = 0x9e3779b9 #magic delta
    # Trong TEA chuẩn, sau 32 vòng encryption, sum sẽ là delta * 32
    sum_val = (delta * 32) & 0xFFFFFFFF
    
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        
    return v0, v1

# 1. Khai báo dữ liệu đầu vào (Ciphertext)
hex_data = "19 2C 30 2A 79 F9 54 02 B3 A9 6C D6 91 80 95 04 29 59 E8 A3 0F 79 BD 86 AF 05 13 6C FE 75 DB 2B AE E0 F0 5D 88 4B 86 89 33 66 AC 45 9A 6C 78 A6"
cipher_bytes = bytes.fromhex(hex_data.replace(" ", ""))

# 2. Khai báo Key (16 bytes)
key_bytes = b"VdlKe9upfBFkkO0L"
# Unpack key thành 4 số nguyên 32-bit (Little-endian)
key = struct.unpack("<4I", key_bytes)

# 3. Giải mã từng khối 8-byte
flag = ""
for i in range(0, len(cipher_bytes), 8):
    if i + 8 <= len(cipher_bytes):
        # Lấy 8 byte ciphertext
        block = struct.unpack("<2I", cipher_bytes[i:i+8])
        # Giải mã
        v0, v1 = decrypt_tea(block, key)
        # Chuyển ngược lại thành ký tự
        flag += struct.pack("<2I", v0, v1).decode('utf-8', errors='ignore')
print(f"Flag: {flag.strip()}")
```

flag thu được: PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}
