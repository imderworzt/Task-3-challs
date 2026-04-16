# Antidebug challs

## 1 anti1.exe

### 1.1 Mở bài và dấu mối quan trọng

- Trong IDA, các điểm cần chốt ngay:
  - `_main` tại `0x401260`.
  - Chuỗi nhập: `Input the flag: ` tại `0x41FA4C`.
  - Key: `BKSEECCCC!!!` tại `0x4218E8`.
  - Hàm transform: `sub_401220` tại `0x401220`.

- Xref cho thấy key chỉ được dùng tại 1 chỗ trong `_main`:
  - `call sub_401220` ngay sau khi đọc input.

### 1.2 Core logic của bài (decompile sub_401220)

<img width="674" height="718" alt="ida_Hix53iojJ9" src="https://github.com/user-attachments/assets/489578a1-5fd3-4500-af1c-90bc946b80c6" />

Decompile cho thấy:

```c
char __fastcall sub_401220(const char *a1, int a2, int i_1)
{
  int key_len = strlen(a1);
  for (int i = 0; i < i_1; ++i)
    *(_BYTE *)(i + a2) ^= a1[i % key_len];
}
```

- Ý nghĩa:
  - `a1` = key (`BKSEECCCC!!!`)
  - `a2` = buffer input
  - `i_1` = số byte xử lý
- Bản chất thuật toán: XOR key lặp lại (Vigenere-XOR style), không có block cipher nào khác.

### 1.3 Luồng _main theo đúng runtime

1. In prompt + scanf `%s` vào stack buffer.
2. Gọi `sub_401220("BKSEECCCC!!!", buf, 0x64)`.
3. Rẽ vào block anti-disasm/anti-debug.
4. Chọn target ciphertext theo nhánh.
5. So sánh 53 byte đầu (`0x35`) của `buf` sau XOR với target.
6. Khác byte nào -> `MessageBoxW("Wrong Flag :((", "Error")` + `ExitProcess`.
7. Đúng hết -> `MessageBoxW("Grab the flag and submit now, what're u waiting for ^^!!", "Congratulation")`.

### 1.4 Anti-disasm: điểm dễ bị nhìn sai flow

- Ngay sau call XOR có byte sequence:
  - `B8 D5 1A 40 00 EB FF ...` (bắt đầu tại `0x40131A`)
- `EB FF` nhảy lùi 1 byte, kéo linear disasm vào trạng thái đọc sai instruction.
- Nếu chỉ tin graph/disasm bị lệch, rất dễ tưởng đây là "junk code vô nghĩa".

### 1.5 Anti-debug thật sự dùng gì?

Khi align đúng luồng chạy, đoạn này trở thành:

- `mov eax, fs:[30h]`  -> lấy PEB
- `cmp byte ptr [eax+2], 0` -> check `BeingDebugged`
- `jz 0x401AD5`

=> Có 2 scenario:
- **Không debug** (`BeingDebugged = 0`) -> nhảy vào `0x401AD5`, nạp target A.
- **Đang debug** (`BeingDebugged = 1`) -> rơi vào nhánh B.

### 1.6 Nhánh B có gì đặc biệt?

- Nhánh B đầy các biểu thức dài trên nhóm 6 byte:
  - nhân 2 byte,
  - `sar 16`,
  - `xor` cặp khác rồi `<<16`,
  - nhân tiếp và `and`,
  - khác 0 thì fail.

- Dạng tổng quát:
  - `(((2*(b0+b1)+1) * ((b2^b3)<<16)) & (((b4*b5)>>16)+1))`
- Vế trái là bội của `2^16`, vế phải sau `>>16`+1 thường về 0/1 -> and = 0.
- Đây là **opaque predicate** để đánh lạc hướng, không phải lớp mã hóa mới.

### 1.7 Hai bộ ciphertext thực tế trong binary

**A) Nhánh non-debug (`jz -> 0x401AD5`)**

<img width="674" height="768" alt="ida_8fhAK1FlWq" src="https://github.com/user-attachments/assets/3d00a6bb-ae00-4d22-837b-c9ba8daedc6a" />

```python
CIPH_NONDBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x26,0x77,0x30,0x58,0x7E,0x42,0x2A,0x7F,0x3F,0x29,
    0x1A,0x21,0x36,0x37,0x1C,0x55,0x49,0x12,0x30,0x78,0x0C,0x28,0x30,0x30,0x37,0x1C,
    0x21,0x12,0x7E,0x52,0x2D,0x26,0x60,0x1A,0x24,0x2D,0x37,0x72,0x1C,0x45,0x44,0x43,
    0x37,0x2C,0x6C,0x7A,0x38
]
```

**B) Nhánh debug (global tại `0x4218B0`)**

<img width="454" height="726" alt="ida_zrxaOn5GYU" src="https://github.com/user-attachments/assets/748c27e8-0cda-4c9b-8425-c8886620cc5a" />

```python
CIPH_DBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x73,0x2D,0x70,0x7E,0x11,0x47,0x1D,0x3F,0x3B,0x76,
    0x1A,0x26,0x77,0x30,0x2A,0x12,0x52,0x55,0x1D,0x28,0x3B,0x24,0x29,0x2F,0x1C,0x2B,
    0x2C,0x51,0x12,0x7E,0x3B,0x7B,0x26,0x1A,0x20,0x2D,0x29,0x73,0x3A,0x7E,0x10,0x55,
    0x1D,0x6A,0x0D,0x1B,0x38
]
```
Thực tế nếu vào graph view khi vừa mở file trong IDA, ta sẽ thấy chuỗi ciphertext của nhánh non-debug.

### 1.8 Cách đảo ngược

Chương trình check:
- `input_xor = input XOR key`
- `input_xor == ciphertext`

Nên recover input:
- `input[i] = ciphertext[i] XOR key[i % len(key)]`

### 1.9 PoC solve (lấy cả 2 kết quả)

```python
KEY = b"BKSEECCCC!!!"

CIPH_NONDBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x26,0x77,0x30,0x58,0x7E,0x42,0x2A,0x7F,0x3F,0x29,
    0x1A,0x21,0x36,0x37,0x1C,0x55,0x49,0x12,0x30,0x78,0x0C,0x28,0x30,0x30,0x37,0x1C,
    0x21,0x12,0x7E,0x52,0x2D,0x26,0x60,0x1A,0x24,0x2D,0x37,0x72,0x1C,0x45,0x44,0x43,
    0x37,0x2C,0x6C,0x7A,0x38
]

CIPH_DBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x73,0x2D,0x70,0x7E,0x11,0x47,0x1D,0x3F,0x3B,0x76,
    0x1A,0x26,0x77,0x30,0x2A,0x12,0x52,0x55,0x1D,0x28,0x3B,0x24,0x29,0x2F,0x1C,0x2B,
    0x2C,0x51,0x12,0x7E,0x3B,0x7B,0x26,0x1A,0x20,0x2D,0x29,0x73,0x3A,0x7E,0x10,0x55,
    0x1D,0x6A,0x0D,0x1B,0x38
]

def recover(cipher):
    return bytes(cipher[i] ^ KEY[i % len(KEY)] for i in range(len(cipher))).decode()

print("[normal path]", recover(CIPH_NONDBG))
print("[debug path ]", recover(CIPH_DBG))
```

Output:
- `[normal path] BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}`
- `[debug path ] BKSEC{0n3_0f_th3_e4si3st_chall_hop3_y0u_enj0y_1t_!^^}`

### 1.10 Kết luận anti1

- Flag: BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}

---

## 2) Replace.exe

### 2.1 Tổng quan nhanh

- `main` nằm tại `0x401250`.
- Các string quan trọng:
  - prompt: `FLAG : `
  - kết quả: `Incorrect` / `Correct`
- Key hardcode trong stack:
  - `VdlKe9upfBFkkO0L` (16 byte)
- Ciphertext compare nằm tại `.data`:
  - `0x40315C`, copy 0x30 byte (48 byte) vào `Buf2`.

### 2.2 Luồng main khi chạy

Trong `_main`, flow rõ ràng như sau:

1. Khởi tạo key 16 byte.
2. `malloc` 2 buffer 0x100 cho input và ciphertext temp.
3. `memcpy(Buf2, 0x40315C, 0x30)`.
4. In `FLAG : `, `fgets` đọc input.
5. Tính độ dài `v10 = strlen(Buffer)`.
6. Nếu `v10 % 8 != 0`:
   - chèn thêm byte `0x0A` (newline) để đủ bội 8.
7. Loop từng block 8 byte:
   - gọi hàm mã hóa.
   - `memcmp(block_input_mahoa, block_ciphertext, 8)`.
   - block nào sai -> `Incorrect` và exit.
8. Qua hết các block -> `Correct`.

### 2.3 Bẫy lớn nhất: TLS callback patch code lúc runtime

Nếu chỉ đọc static, ta thấy `_main` gọi `sub_401180` tại `0x4013A2`.

<img width="352" height="368" alt="ida_kqMf6iThTH" src="https://github.com/user-attachments/assets/c5be79e4-4a94-44bb-8610-8d085597b2f9" />

Nhưng `TlsCallback_0` (`0x401000`) làm việc sau:

- `if (!IsDebuggerPresent())` thì:
  - `WriteProcessMemory(hProcess, 0x4013A3, lpBuffer_, 4, ...)`

<img width="339" height="264" alt="ida_OcFtQP4wfT" src="https://github.com/user-attachments/assets/b5c9a945-9025-46de-9ac7-4fbb99be7122" />

Chi tiết byte:

- Call gốc tại `0x4013A2`:
  - `E8 D9 FD FF FF` -> target `0x401180`
- `lpBuffer_` tại `0x403140`:
  - `C9 FC FF FF`
- Sau patch:
  - call thành `E8 C9 FC FF FF` -> target `0x401070`

=> Kết luận:
- **Chạy bình thường (không debug)**: call bị patch sang `sub_401070`.
- **Đang debug**: không patch, vẫn gọi `sub_401180`.

### 2.4 Vì sao dễ bị nhầm hướng?

- `sub_401180` (nhánh debug) chỉ là XOR đơn giản trên 2 dword:
  - `v0 ^= (k0 + k1)`
  - `v1 ^= (k2 + k3)`
- Nếu dùng nhánh này để đảo ngược ciphertext, kết quả ra gibberish không phải flag.

<img width="439" height="151" alt="ida_8Ttn3AjtkT" src="https://github.com/user-attachments/assets/ef3810f4-e185-44bd-a99b-9f551440b821" />

- Hàm đúng để solve là `sub_401070` (nhánh non-debug):
  - loop 32 round,
  - dùng hằng `0x9E3779B9`,
  - công thức `<<4`, `>>5`, xor/sum trên cặp `v0, v1`.

=> Đây là TEA variant (được gọi thông qua self-patch ở TLS).

<img width="512" height="351" alt="ida_1iHANPe78v" src="https://github.com/user-attachments/assets/66dae7d0-ec02-40db-ae82-06d124d030b1" />

### 2.5 Phân tích sub_401070 (hàm thật sự được gọi)

Pseudo rút gọn:

```c
v0 = block[0];
v1 = block[1];
sum = 0;
for (i=0; i<32; i++) {
    sum -= 0x61C88647; // tương đương cộng delta âm
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
}
block[0] = v0;
block[1] = v1;
```

- Khóa 16-byte:
  - `k = struct.unpack("<4I", b"VdlKe9upfBFkkO0L")`
- Ciphertext:
  - 48 byte tại `0x40315C`
  - xử lý theo block 8 byte little-endian.

### 2.6 Cách đảo ngược đúng

- Chương trình mã hóa input rồi so sánh với ciphertext.
- Để recover input đúng:
  1. Lấy 48 byte ciphertext.
  2. Chạy **TEA decrypt** block-by-block với cùng key.
  3. Plain ra được gồm:
     - flag thật sự
     - kèm padding theo logic newline.

### 2.7 PoC solve tự động

```python
import struct

def decrypt_tea(v, k):
    v0, v1 = v
    k0, k1, k2, k3 = k
    delta = 0x9E3779B9
    s = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return v0, v1

cipher = bytes.fromhex(
    "19 2C 30 2A 79 F9 54 02 B3 A9 6C D6 91 80 95 04 "
    "29 59 E8 A3 0F 79 BD 86 AF 05 13 6C FE 75 DB 2B "
    "AE E0 F0 5D 88 4B 86 89 33 66 AC 45 9A 6C 78 A6"
)
key = struct.unpack("<4I", b"VdlKe9upfBFkkO0L")

plain = bytearray()
for i in range(0, len(cipher), 8):
    v0, v1 = struct.unpack("<2I", cipher[i:i+8])
    p0, p1 = decrypt_tea((v0, v1), key)
    plain += struct.pack("<2I", p0, p1)

print("raw:", repr(plain))

# Cắt flag đến dấu '}' để bỏ phần padding newline/null
flag = plain.split(b"}", 1)[0] + b"}"
print("flag:", flag.decode())
```

### 2.8 Kết quả

- Plain full (48 byte) có dạng:
  - `PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}` + padding (`\\n...\\x00`)
- Flag cần nộp:
  - `PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}`
---

## 3) ThitNhi.exe

### 3.1 Tổng quan nhanh (từ IDA-MCP)

- Hàm chính: `_main` tại `0x401300`.
- String:
  - `Enter Flag :`
  - `Failed`
  - `Success!! Here is your Flag : Flag{%s}`

- Hai hàm quan trọng:
  - `sub_401120` (`0x401120`): RC4 implementation.
  - cặp anti-debug key-logic:
    - `sub_401080` (`0x401080`)
    - `sub_4010C0` (`0x4010C0`)

### 3.2 Luồng _main

Trong `_main`, flow như sau:

1. In prompt, `fgets(Buffer, 14, stdin)`.
2. Khởi tạo target ciphertext 13 byte:
   - `7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4`
3. Tính biến `v7` (4 byte key seed) qua anti-debug:
   - `v4 = sub_401080(main)`
   - `v7 = sub_4010C0(main, v4) ^ 0xDEADBEEF`
4. Gọi `sub_401120(Buffer, 13, &v7, 4, v9)`.
5. So sánh `v9` với target 13 byte.
6. Match -> in `Success!! Here is your Flag : Flag{%s}` với `%s = Buffer`.

### 3.3 Phân tích anti-debug key derivation

#### a) `sub_401080`
- Chức năng: đếm số byte từ đầu hàm đến byte `0xC3` đầu tiên (opcode `retn`).
- Pseudo:
  - tăng con trỏ từng byte,
  - dừng khi gặp byte `0xC3`,
  - trả về độ dài đoạn đã quét.

#### b) `sub_4010C0`
- Chức năng: quét `i_1` byte đầu của một hàm:
  - nếu có byte `0xCC` -> return `19`
  - ngược lại -> return `55`

<img width="635" height="303" alt="ida_bSLBGBnYhr" src="https://github.com/user-attachments/assets/9b90983c-808c-41b8-818d-5ec8c9ca7bad" />

#### c) Giá trị thực tế (xác nhận bằng py_eval trong IDA)
- Cho `_main`:
  - độ dài đến `0xC3`: `287`
  - có `0xCC` (offset 46) -> `sub_4010C0(main, 287) = 19`
- Cho `sub_401120`:
  - độ dài đến `0xC3`: `476`
  - không có `0xCC` -> `sub_4010C0(sub_401120, 476) = 55`

=> Key seed:
- `v7_initial = 19 ^ 0xDEADBEEF = 0xDEADBEFC`
- Trong `sub_401120`: `*a3 = *a3 + 55`
- `v7_final = 0xDEADBEFC + 0x37 = 0xDEADBF33`
- Little-endian key bytes dùng trong RC4 KSA:
  - `33 BF AD DE`

### 3.4 `sub_401120` là RC4

Decompile cho thấy đủ mẫu RC4:

1. Khởi tạo S-box 256 phần tử.
2. KSA:
   - S[i] swap theo key byte `*((BYTE*)a3 + i % n4)` với `n4 = 4`.
3. PRGA:
   - sinh keystream từ S-box.
   - `out[k] = keystream ^ Buffer[k]`.

Trong `_main`:
- `n13 = 13` -> mã hóa 13 byte đầu của input.
- output đặt vào `v9` rồi `memcmp` với target.

### 3.5 Cách giải

- Vì RC4 đối xứng, decrypt cũng chính là RC4 với cùng key.
- Ta lấy:
  - ciphertext: `7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4`
  - key: `33 BF AD DE`
- RC4 decrypt -> plain:
  - `D1t_m3_H4_N41`

### 3.6 PoC solve sử dụng Cyberchef để decrypt

<img width="1537" height="977" alt="yQ9BWpfus9" src="https://github.com/user-attachments/assets/ed088ec9-010c-4958-a204-cc2b5468534f" />

### 3.7 Kết quả

- Plain pass: `D1t_m3_H4_N41`
- Flag: `Flag{D1t_m3_H4_N41}`

## 4) n1gg4.exe

### 4.1 Phân tích đầu bài

- Mẫu ban đầu đóng gói (UPX lỗi header), nên cần dump/fix IAT rồi mới đọc được.
- Sau khi clean file và xem được logic:
  - Có vòng lặp ngoài xử lý từng byte.
  - Có vòng lặp trong XOR theo key pattern, phụ thuộc `dword_403710`.
  - Sau đó có bước `neg al` (đảo dấu byte).

- Điều quan trọng:
  - `dword_403710 = 0`
  - => vòng XOR trong không chạy.
  - => transform còn lại chủ yếu là `byte = (-byte) & 0xFF`.

### 4.2 Vấn đề

- Dữ liệu plaintext bị cắt thành nhiều segment ở nhiều địa chỉ.
- Nếu decrypt từng đoạn không đúng thứ tự sẽ ra string "đúng ký tự nhưng sai nghĩa".

### 4.3 Cách handle

1. Trích từng segment enc.
2. Mỗi byte áp dụng `(-b) & 0xFF`.
3. Ghép theo thứ tự đúng để ra câu pass hoàn chỉnh.

### 4.4 PoC solve

```python
seg1 = bytes.fromhex(
    "00 AD 8C C0 9D 95 AC CF 93 CD BD BD AD CD 94 9A D3 B0 CD BE BA CF 92 9C "
    "A9 CF 92 9C D0 89 B8 CF 9C CF 92 99 C0 92 8C CF D3 AE CD 8A CD 8E 8D CD"
)
seg2 = bytes.fromhex("B2 8C AF 8B CD 8E 87 CF 92 9A D0 8E 93 C0 8C CF D0 92 B0 8E D0 D8 CD CB CB")
seg3 = bytes.fromhex("AE C0 DF 8D CD CD 88 9D CD 90 8C DF 91 92")
seg4 = bytes.fromhex("BC CD 9E 8B 99 B0 8E CF 8A CF 94 CD 99 CD")

def dec_neg(bs):
    return bytes(((-b) & 0xFF) for b in bs)

p1 = dec_neg(seg1).decode()
p2 = dec_neg(seg2).decode()
p3 = dec_neg(seg3).decode()
p4 = dec_neg(seg4).decode()

print("seg1:", p1)
print("seg2:", p2)
print("seg3:", p3)
print("seg4:", p4)

# Thứ tự ghép đúng theo flow
full = p2 + p3 + p4 + p1
print("full:", full)
```

### 4.5 Kết quả

- Recover được chuỗi anti-debug đầy đủ để nhập vào chương trình.
- Các segment giải ra (ghép lại vào nhau là xong):
  - `St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3`
  - `NtQu3ry1nf0rm@t10nPr0(355`
  - `R@!s33xc3pt!on`
  - `D3bugPr1v1l3g3`

---

## 5) antidebug3.exe

### 5.1 Phân tích đầu bài

- `_main` (`0x4015B0`) không xử lý input theo flow thông thường. Nó:
  - `SetUnhandledExceptionFilter(TopLevelExceptionFilter)`
  - Cố tình tạo exception (chia 0 / software interrupt) để nhảy vào handler.
- Vì vậy, flow chính của chall nằm trong `TopLevelExceptionFilter` (`0x4014C0`), không nằm ở phần main decompile "đẹp".

- Đoạn đầu `TopLevelExceptionFilter` có anti-disasm:
  - `jz` + `jnz` đều nhảy vào giữa instruction (kiểu jump-into-middle).
  - Nếu không undefine/redefine code, IDA sẽ tạo ra call rác.
  - Decode lại đúng thì thấy:
    - `byte_404082 = BeingDebugged ^ 0xAB`
    - `byte_404083 = v3 ^ 0xCD` (v3 từ check PEB/NtGlobalFlag-like)

- Hàm compare cuối cùng là `sub_401100`:
  - So sánh `byte_404640[i]` với `byte_404118[i]` trong 100 byte.
  - In `Status: x/100`.
  - Đúng 100/100 thì in `You got it! flag: kcsc{%s}` với `%s = unk_404560`.

### 5.2 Vấn đề

- Khó nhất là bài này không có "1 hàm mã hóa" đơn lẻ, mà là pipeline nhiều block, mỗi block xử lý 1 đoạn offset.
- `sub_401400` scan opcode `0xCC` trong vùng `sub_401330`:
  - `return i_1 - i + 0xBEEF`.
  - Chạy thường: không có `0xCC` => kết quả đúng bằng `0xBEEF`.
  - Nếu đặt software breakpoint (patch `0xCC`) vào vùng bị quét, giá trị này đổi và làm hướng xử lý sai.
- 1 block khác phụ thuộc `BeingDebugged`:
  - Chạy thường: xor với `0xAB`.
  - Đang debug: xor với `0xAA`.

### 5.3 Tách block transform

`TopLevelExceptionFilter` copy input vào `0x404560`, tính key, rồi gọi `sub_401460(0x404652)`.
Từ disasm/pseudocode có thể tách được block theo offset trong buffer 100 byte như sau:

1. Offset `0..16`: `buf[i] ^= 1`
2. Offset `18..25`: `buf[i] ^= (BeingDebugged ^ 0xAB)`  
   - run bình thường => `BeingDebugged = 0` => xor `0xAB`
3. Offset `27..38`:  
   `out = (0xCD + i) ^ (((x << 1) & 0xFF) | 1)`  
   - đảo ngược cần brute-force trong bộ ký tự hợp lý
4. Offset `40..57`: xor word với `0xBEEF`
5. Offset `59..63`: `ror8(buf[i], i)` -> đảo ngược bằng `rol8`
6. Offset `65..68`: xor dword `0xC0FE1337`
7. Offset `70..99`: xor-chain liên tiếp (`buf[i] ^= buf[i-1]`)  
   - đảo ngược phải đi ngược từ cuối về đầu.

### 5.4 Cách handle

- Lấy 100-byte target ở `0x404118` (chuỗi bắt đầu bằng `74 6F 69 35 4F 65 ...`).
- Reverse theo thứ tự ngược: block `7 -> 1`.
- Ở block 3, nghịch đảo không 1-1 nếu không ràng buộc ký tự, nên brute-force trên alphabet:
  - `[a-zA-Z0-9_]`
- Chọn scenario chạy thường (`BeingDebugged=0`) để dùng key `0xAB` cho block 2.

### 5.5 PoC solve

```python
import struct
import string

TARGET = bytes.fromhex(
    "746f69354f656d3232794232715568316f5f"
    "dbcec9efcec9fe92"
    "5f"
    "1027bc090e17ba4d180fbeab"
    "5f"
    "9c8ea989988a9d8dd7ccdc8aa4cedf8f8189"
    "5f"
    "69371d46465f5e7d8af3"
    "5f"
    "5901576706417801652d7b0e5703685d076923553760147e1d2f625f625f"
)

ALPHABET = (string.ascii_letters + string.digits + "_").encode()

def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF

def recover(target: bytes, being_debugged: int = 0) -> str:
    buf = bytearray(target)

    # Block 7: reverse xor-chain 70..99
    for i in range(29, 0, -1):
        buf[70 + i] ^= buf[70 + i - 1]

    # Block 6: reverse dword xor at 65..68
    d = struct.unpack_from("<I", buf, 65)[0] ^ 0xC0FE1337
    struct.pack_into("<I", buf, 65, d)

    # Block 5: reverse ror8 => rol8 at 59..63
    for i in range(5):
        buf[59 + i] = rol8(buf[59 + i], i)

    # Block 4: reverse 0xBEEF word xor at 40..57
    for i in range(9):
        idx = 40 + i * 2
        w = (buf[idx] | (buf[idx + 1] << 8)) ^ 0xBEEF
        buf[idx] = w & 0xFF
        buf[idx + 1] = (w >> 8) & 0xFF

    # Block 3: reverse ((x<<1)|1) xor key at 27..38
    for i in range(12):
        idx = 27 + i
        z = buf[idx] ^ ((0xCD + i) & 0xFF)
        cand = [c for c in ALPHABET if ((((c << 1) & 0xFF) | 1) == z)]
        if len(cand) != 1:
            raise ValueError(f"ambiguous inverse at idx={idx}: {cand}")
        buf[idx] = cand[0]

    # Block 2: reverse xor (BeingDebugged ^ 0xAB) at 18..25
    k = (being_debugged & 1) ^ 0xAB
    for i in range(8):
        buf[18 + i] ^= k

    # Block 1: reverse xor 1 at 0..16
    for i in range(17):
        buf[i] ^= 1

    return bytes(buf).decode()

inner = recover(TARGET, being_debugged=0)
print(inner)
print(f"kcsc{{{inner}}}")
```

### 5.6 Kết quả

- Chuỗi recover:
  - `unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===`
- Flag:
  - `kcsc{unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===}`

---

## 6) harder-medium-antidebug.exe

### 6.1 Phân tích đầu bài

- `main` cực ngắn:
  - `int3`
  - `call off_7FF7630C83B0`
  - `call main` (đệ quy tiếp)
- Nghĩa là mỗi vòng lặp sẽ có 1 `int3`, và logic thật sự nằm trong exception flow.

- Handler chính: `sub_7FF7630BC7C0` (đăng ký bằng `RtlAddVectoredExceptionHandler` trong `sub_7FF7630BC950`).
- Handler chỉ nhận `EXCEPTION_BREAKPOINT (0x80000003)`, rồi:
  1. Lấy index tiếp theo từ `dword_7FF7630C5740[n2831++]`
  2. Lấy function pointer `off_7FF7630BE2D0[index]`
  3. `VirtualProtect` 12 bytes ở thunk `off_7FF7630C83B0`
  4. Patch thunk thành `48 B8 <addr> FF E0` (`mov rax, addr ; jmp rax`)
  5. Return `-1` để tiếp tục execution

- Tức là chall này dùng kiểu exception-dispatch VM: mỗi lần `int3` sẽ chạy 1 hàm trong bảng đã shuffle.

### 6.2 Vấn đề

- Có 2 lớp anti-debug:
  1. Điều khiển flow bằng exception + runtime code patch
  2. Check `IsDebuggerPresent` để đổi nhánh

- `dword_7FF7630C5740` không có thứ tự cố định trong file, mà được tạo runtime:
  - `sub_7FF7630BCA20`: `arr[i] = i`, `srand(0x539)`
  - `sub_7FF7630BC9D0`: Fisher-Yates shuffle bằng `rand()`
- Đặt software breakpoint bừa bãi rất dễ làm sai flow.

### 6.3 Các breakpoint cần đặt và làm gì khi step đến

- .text:00007FF67FC4C78A mov     cs:dword_7FF67FC583B8, eax
    - Câu lệnh này gọi IsDebuggerPresent và lưu kết quả vào thanh ghi RAX trong ida.
    - Khi debug, breakpoint này sẽ là thứ đến đầu tiên, RAX sẽ bằng 1, cần chỉnh về 0 rồi step tiếp
- text:00007FF67FC4C667 call    cs:off_7FF67FC58390
    - Đơn giản đây là hàm nhập password, hãy nhập password là 12345678 rồi step tiếp
- .text:00007FF67FC48354 mov     cs:qword_7FF67FC556E0, rax
    - Nó gọi hàm SystemFunction032 trong thư viện động Cryptsp.dll, chuyển đến thanh ghi RAX để thực hiện.
- .text:00007FF67FC48394 mov     cs:qword_7FF67FC55720, rax
    - Nó gọi hàm SystemFunction002 trong Cryptsp.dll, tương tự với lệnh ở trên
- Khi debug nó sẽ chạy xung quanh 2 cái hàm này và tạo thành 1 cái flow để mã hóa password chúng ta vừa nhập. Flow này sẽ được nói ở dưới đây

### 6.4 Tách crypto chain và key material

- Resolve hash trong `sub_7FF7630B1050` cho thấy:
  - `sub_7FF7630BC680` -> `SystemFunction033` (RC4)
  - `sub_7FF7630BC6A0` -> `SystemFunction002` (DES block transform)

- Data:
  - Key material tại `0x7FF7630C5078`: `"12345678"`
  - Target tại `0x7FF7630C5080`: `24 28 14 4A 11 A0 7F E4`

- Thứ tự crypto thực tế (slot `1780..1787`):
  - `RC4, DES, RC4, RC4, DES, DES, DES, RC4`
  - Hai lần RC4 liên tiếp giữa chain triệt tiêu nhau.
  - Chain rút gọn:
    - `C = RC4(DES(DES(DES(DES(RC4(P))))))`

- Với `SystemFunction002`, key DES hiệu dụng là 56-bit packed từ 7 byte đầu của `"12345678"`:
  - `31 32 33 34 35 36 37` -> `30 98 8C 66 42 A8 D8 6E`

### 6.5 PoC solve

```python
from Crypto.Cipher import ARC4, DES

# pip install pycryptodome

C = bytes.fromhex("24 28 14 4A 11 A0 7F E4")
rc4_key = b"12345678"

def expand_des_key_7_to_8_no_parity(k7: bytes) -> bytes:
    assert len(k7) == 7
    return bytes([
        k7[0] & 0xFE,
        ((k7[0] << 7) | (k7[1] >> 1)) & 0xFE,
        ((k7[1] << 6) | (k7[2] >> 2)) & 0xFE,
        ((k7[2] << 5) | (k7[3] >> 3)) & 0xFE,
        ((k7[3] << 4) | (k7[4] >> 4)) & 0xFE,
        ((k7[4] << 3) | (k7[5] >> 5)) & 0xFE,
        ((k7[5] << 2) | (k7[6] >> 6)) & 0xFE,
        (k7[6] << 1) & 0xFE,
    ])

des_key = expand_des_key_7_to_8_no_parity(rc4_key[:7])
print("DES key =", des_key.hex())  # 30988c6642a8d86e

# Inverse chain:
# P = RC4( DES_ENC^4( RC4(C) ) )
x = ARC4.new(rc4_key).encrypt(C)
for _ in range(4):
    x = DES.new(des_key, DES.MODE_ECB).encrypt(x)
P = ARC4.new(rc4_key).encrypt(x)

print(P.decode())
```

### 6.6 Kết quả

- Password recover: `debugger`
- Chạy binary và nhập `debugger` -> `Correct!`

---

## 7) anti3.exe

### 7.1 Phân tích đầu bài

- Bài này là GUI x86, xử lý chính ở `sub_401350` (WndProc).
- Khi bấm `Login :)` (id `4`), flow:
  1. `GetWindowTextA` lấy input.
  2. `sub_401B40(input)` kiểm tra pass (38 vòng state-machine).
  3. `sub_401000(input, out_buf, &len)` decrypt thông báo bằng CryptoAPI.
  4. Nếu `len == 0x2E` thì messagebox hiện plaintext.

- Ciphertext (48 byte) tại `0x4038D0`:
  - `5f16bac1246deeca6e6fd56fd2997666799293ee8f20cbc932cb756e80235da661f79ca2156b6e5d180932ee3fe43adc`

<img width="737" height="35" alt="ida_k06LfNmhK8" src="https://github.com/user-attachments/assets/72bd6215-2b1e-4e8d-ba8c-36dc7bb4b12a" />

### 7.2 Vấn đề

- `sub_401B40` không so chuỗi trực tiếp mà dùng bảng điều khiển:
  - `dword_4032C8` (op-code),
  - `dword_403360` (param),
  - `dword_4033F8` (vị trí ký tự),
  - `byte_40329F` (expected).

- Mỗi vòng có công thức:
  - `expected = input[idx] ^ prng_byte`
  - => đảo ngược: `input[idx] = expected ^ prng_byte`

- Khó ở chỗ `prng_byte` phụ thuộc anti-debug (`dl` bit), nên debug trực tiếp dễ ra sai pass.

### 7.3 Cách xử lý

1. Mô hình hóa đúng `sub_401FD0` + `sub_402050` (state + PRNG).
2. Tính seed từ bảng `0x40501C`:
   - `seed_signed = 117`
  
     <img width="664" height="113" alt="ida_CLj9sdZ65O" src="https://github.com/user-attachments/assets/ad9c90c0-840c-49b0-8440-1ad2f5d2d72c" />

3. Brute-force 7 bit môi trường anti-debug:
   - `d1,d2,d3,d4,d5,d7,eqbit` (128 trường hợp).
4. Lọc nghiệm printable ASCII.

### 7.4 PoC solve

```python
import importlib.util
import pathlib
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# pip install pycryptodome

MOD_PATH = r"D:\university\ctf\anti-debugger\anti3_solver.py"
EXE_PATH = r"D:\university\ctf\anti-debugger\anti3.exe"
CT = bytes.fromhex(
    "5f16bac1246deeca6e6fd56fd2997666"
    "799293ee8f20cbc932cb756e80235da6"
    "61f79ca2156b6e5d180932ee3fe43adc"
)

spec = importlib.util.spec_from_file_location("a3", MOD_PATH)
a3 = importlib.util.module_from_spec(spec)
sys.modules["a3"] = a3
spec.loader.exec_module(a3)

data = pathlib.Path(EXE_PATH).read_bytes()
pe = a3.parse_pe(data)
tables = a3.extract_tables(pe, data)
seed = a3.compute_seed_signed(pe, data)

for d1 in (0, 1):
    for d2 in (0, 1):
        for d3 in (0, 1):
            for d4 in (0, 1):
                for d5 in (0, 1):
                    for d7 in (0, 1):
                        for eq in (0, 1):
                            bits = a3.EnvBits(d1, d2, d3, d4, d5, d7, eq)
                            try:
                                pw = a3.recover_key(tables, seed, bits)
                            except Exception:
                                continue
                            aes_key = hashlib.sha256(pw.encode()).digest()[:16]
                            try:
                                pt = unpad(AES.new(aes_key, AES.MODE_CBC, b"\x00" * 16).decrypt(CT), 16).decode()
                            except Exception:
                                continue
print (pw)
```

### 7.5 Kết quả

- `I_10v3-y0U__wh3n Y0u=c411..M3 Senor1t4`

<img width="1426" height="782" alt="anti3_gAPIWaWoVg" src="https://github.com/user-attachments/assets/3251d71c-d28a-4073-a299-98d56d960508" />
