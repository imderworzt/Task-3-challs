# Antidebug challs

## 1 anti1.exe

### 1.1 Mo bai va dau moi quan trong

- Trong IDA , cac diem can chot ngay:
  - `_main` tai `0x401260`.
  - Chuoi nhap: `Input the flag: ` tai `0x41FA4C`.
  - Key: `BKSEECCCC!!!` tai `0x4218E8`.
  - Ham transform: `sub_401220` tai `0x401220`.

- Xref cho thay key chi duoc dung tai 1 cho trong `_main`:
  - `call sub_401220` ngay sau khi doc input.

### 1.2 Core logic cua bai (decompile sub_401220)

<img width="674" height="718" alt="ida_Hix53iojJ9" src="https://github.com/user-attachments/assets/489578a1-5fd3-4500-af1c-90bc946b80c6" />

Decompile cho thay:

```c
char __fastcall sub_401220(const char *a1, int a2, int i_1)
{
  int key_len = strlen(a1);
  for (int i = 0; i < i_1; ++i)
    *(_BYTE *)(i + a2) ^= a1[i % key_len];
}
```

- Y nghia:
  - `a1` = key (`BKSEECCCC!!!`)
  - `a2` = buffer input
  - `i_1` = so byte xu ly
- Ban chat thuat toan: XOR key lap lai (Vigenere-XOR style), khong co block cipher nao khac.

### 1.3 Luong _main theo dung runtime

1. In prompt + scanf `%s` vao stack buffer.
2. Goi `sub_401220("BKSEECCCC!!!", buf, 0x64)`.
3. Re vao block anti-disasm/anti-debug.
4. Chon target ciphertext theo nhanh.
5. So sanh 53 byte dau (`0x35`) cua `buf` sau XOR voi target.
6. Khac byte nao -> `MessageBoxW("Wrong Flag :((", "Error")` + `ExitProcess`.
7. Dung het -> `MessageBoxW("Grab the flag and submit now, what're u waiting for ^^!!", "Congratulation")`.

### 1.4 Anti-disasm: diem de bi nhin sai flow

- Ngay sau call XOR co byte sequence:
  - `B8 D5 1A 40 00 EB FF ...` (bat dau tai `0x40131A`)
- `EB FF` nhay lui 1 byte, keo linear disasm vao trang thai doc sai instruction.
- Neu chi tin graph/disasm bi lech, rat de tuong day la "junk code vo nghia".

### 1.5 Anti-debug that su dung gi?

Khi align dung luong chay, doan nay tro thanh:

- `mov eax, fs:[30h]`  -> lay PEB
- `cmp byte ptr [eax+2], 0` -> check `BeingDebugged`
- `jz 0x401AD5`

=> Co 2 scenario:
- **Khong debug** (`BeingDebugged = 0`) -> nhay vao `0x401AD5`, nap target A.
- **Dang debug** (`BeingDebugged = 1`) -> roi vao nhanh B.

### 1.6 Nhanh B co gi dac biet?

- Nhanh B day cac bieu thuc dai tren nhom 6 byte:
  - nhan 2 byte,
  - `sar 16`,
  - `xor` cap khac roi `<<16`,
  - nhan tiep va `and`,
  - khac 0 thi fail.

- Dang tong quat:
  - `(((2*(b0+b1)+1) * ((b2^b3)<<16)) & (((b4*b5)>>16)+1))`
- Ve trai la boi cua `2^16`, ve phai sau `>>16`+1 thuong ve 0/1 -> and = 0.
- Day la **opaque predicate** de danh lac huong, khong phai lop ma hoa moi.

### 1.7 Hai bo ciphertext thuc te trong binary

**A) Nhanh non-debug (`jz -> 0x401AD5`)**

<img width="674" height="768" alt="ida_8fhAK1FlWq" src="https://github.com/user-attachments/assets/3d00a6bb-ae00-4d22-837b-c9ba8daedc6a" />

```python
CIPH_NONDBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x26,0x77,0x30,0x58,0x7E,0x42,0x2A,0x7F,0x3F,0x29,
    0x1A,0x21,0x36,0x37,0x1C,0x55,0x49,0x12,0x30,0x78,0x0C,0x28,0x30,0x30,0x37,0x1C,
    0x21,0x12,0x7E,0x52,0x2D,0x26,0x60,0x1A,0x24,0x2D,0x37,0x72,0x1C,0x45,0x44,0x43,
    0x37,0x2C,0x6C,0x7A,0x38
]
```

**B) Nhanh debug (global tai `0x4218B0`)**

<img width="454" height="726" alt="ida_zrxaOn5GYU" src="https://github.com/user-attachments/assets/748c27e8-0cda-4c9b-8425-c8886620cc5a" />

```python
CIPH_DBG = [
    0x00,0x00,0x00,0x00,0x06,0x38,0x73,0x2D,0x70,0x7E,0x11,0x47,0x1D,0x3F,0x3B,0x76,
    0x1A,0x26,0x77,0x30,0x2A,0x12,0x52,0x55,0x1D,0x28,0x3B,0x24,0x29,0x2F,0x1C,0x2B,
    0x2C,0x51,0x12,0x7E,0x3B,0x7B,0x26,0x1A,0x20,0x2D,0x29,0x73,0x3A,0x7E,0x10,0x55,
    0x1D,0x6A,0x0D,0x1B,0x38
]
```
Thực tế ra nếu vào graph view khi vừa mở file trong IDA, ta sẽ thấy chuỗi ciphertext của nhánh non-debug

### 1.8 Cach dao nguoc

Chuong trinh check:
- `input_xor = input XOR key`
- `input_xor == ciphertext`

Nen recover input:
- `input[i] = ciphertext[i] XOR key[i % len(key)]`

### 1.9 PoC solve (lay ca 2 ket qua)

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

### 1.10 Ket luan anti1

- Flag: BKSEC{e4sy_ch4ll_but_th3r3_must_b3_som3_ant1_debug??}

---

## 2) Replace.exe

### 2.1 Tong quan nhanh

- `main` nam tai `0x401250`.
- Cac string quan trong:
  - prompt: `FLAG : `
  - ket qua: `Incorrect` / `Correct`
- Key hardcode trong stack:
  - `VdlKe9upfBFkkO0L` (16 byte)
- Ciphertext compare nam tai `.data`:
  - `0x40315C`, copy 0x30 byte (48 byte) vao `Buf2`.

### 2.2 Luong main khi chay

Trong `_main`, flow ro rang nhu sau:

1. Khoi tao key 16 byte.
2. `malloc` 2 buffer 0x100 cho input va ciphertext temp.
3. `memcpy(Buf2, 0x40315C, 0x30)`.
4. In `FLAG : `, `fgets` doc input.
5. Tinh do dai `v10 = strlen(Buffer)`.
6. Neu `v10 % 8 != 0`:
   - chen them byte `0x0A` (newline) de du boi 8.
7. Loop tung block 8 byte:
   - goi ham ma hoa.
   - `memcmp(block_input_mahoa, block_ciphertext, 8)`.
   - block nao sai -> `Incorrect` va exit.
8. Qua het cac block -> `Correct`.

### 2.3 Bay lon nhat: TLS callback patch code luc runtime

Neu chi doc static, ta thay `_main` goi `sub_401180` tai `0x4013A2`.

<img width="352" height="368" alt="ida_kqMf6iThTH" src="https://github.com/user-attachments/assets/c5be79e4-4a94-44bb-8610-8d085597b2f9" />

Nhung `TlsCallback_0` (`0x401000`) lam viec sau:

- `if (!IsDebuggerPresent())` thi:
  - `WriteProcessMemory(hProcess, 0x4013A3, lpBuffer_, 4, ...)`

<img width="339" height="264" alt="ida_OcFtQP4wfT" src="https://github.com/user-attachments/assets/b5c9a945-9025-46de-9ac7-4fbb99be7122" />

Chi tiet byte:

- Call goc tai `0x4013A2`:
  - `E8 D9 FD FF FF` -> target `0x401180`
- `lpBuffer_` tai `0x403140`:
  - `C9 FC FF FF`
- Sau patch:
  - call thanh `E8 C9 FC FF FF` -> target `0x401070`

=> Ket luan:
- **Chay binh thuong (khong debug)**: call bi patch sang `sub_401070`.
- **Dang debug**: khong patch, van goi `sub_401180`.

### 2.4 Vi sao de bi nham huong?

- `sub_401180` (nhanh debug) chi la XOR don gian tren 2 dword:
  - `v0 ^= (k0 + k1)`
  - `v1 ^= (k2 + k3)`
- Neu dung nhanh nay de dao nguoc ciphertext, ket qua ra gibberish khong phai flag.

<img width="439" height="151" alt="ida_8Ttn3AjtkT" src="https://github.com/user-attachments/assets/ef3810f4-e185-44bd-a99b-9f551440b821" />

- Ham dung de solve la `sub_401070` (nhanh non-debug):
  - loop 32 round,
  - dung hang `0x9E3779B9`,
  - cong thuc `<<4`, `>>5`, xor/sum tren cap `v0, v1`.

=> Day la TEA variant (duoc goi thong qua self-patch o TLS).

<img width="512" height="351" alt="ida_1iHANPe78v" src="https://github.com/user-attachments/assets/66dae7d0-ec02-40db-ae82-06d124d030b1" />

### 2.5 Phan tich sub_401070 (ham that su duoc goi)

Pseudo rut gon:

```c
v0 = block[0];
v1 = block[1];
sum = 0;
for (i=0; i<32; i++) {
    sum -= 0x61C88647; // tuong duong cong delta am
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
}
block[0] = v0;
block[1] = v1;
```

- Khoa 16-byte:
  - `k = struct.unpack("<4I", b"VdlKe9upfBFkkO0L")`
- Ciphertext:
  - 48 byte tai `0x40315C`
  - xu ly theo block 8 byte little-endian.

### 2.6 Cach dao nguoc dung

- Chuong trinh ma hoa input roi so sanh voi ciphertext.
- De recover input dung:
  1. Lay 48 byte ciphertext.
  2. Chay **TEA decrypt** block-by-block voi cung key.
  3. Plain ra duoc gom:
     - flag that su
     - kem padding theo logic newline.

### 2.7 PoC solve tu dong

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

# Cat flag den dau '}' de bo phan padding newline/null
flag = plain.split(b"}", 1)[0] + b"}"
print("flag:", flag.decode())
```

### 2.8 Ket qua

- Plain full (48 byte) co dang:
  - `PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}` + padding (`\\n...\\x00`)
- Flag can nop:
  - `PTITCTF{bdc90e23aa0415e94d0ac46a938efcf3}`
---

## 3) ThitNhi.exe

### 3.1 Tong quan nhanh (tu IDA-MCP)

- Ham chinh: `_main` tai `0x401300`.
- String:
  - `Enter Flag :`
  - `Failed`
  - `Success!! Here is your Flag : Flag{%s}`

- Hai ham quan trong:
  - `sub_401120` (`0x401120`): RC4 implementation.
  - cap anti-debug key-logic:
    - `sub_401080` (`0x401080`)
    - `sub_4010C0` (`0x4010C0`)

### 3.2 Luong _main

Trong `_main`, flow nhu sau:

1. In prompt, `fgets(Buffer, 14, stdin)`.
2. Khoi tao target ciphertext 13 byte:
   - `7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4`
3. Tinh bien `v7` (4 byte key seed) qua anti-debug:
   - `v4 = sub_401080(main)`
   - `v7 = sub_4010C0(main, v4) ^ 0xDEADBEEF`
4. Goi `sub_401120(Buffer, 13, &v7, 4, v9)`.
5. So sanh `v9` voi target 13 byte.
6. Match -> in `Success!! Here is your Flag : Flag{%s}` voi `%s = Buffer`.

### 3.3 Phan tich anti-debug key derivation

#### a) `sub_401080`
- Chuc nang: dem so byte tu dau ham den byte `0xC3` dau tien (opcode `retn`).
- Pseudo:
  - tang con tro tung byte,
  - dung khi gap byte `0xC3`,
  - tra ve do dai doan da quet.

#### b) `sub_4010C0`
- Chuc nang: quet `i_1` byte dau cua mot ham:
  - neu co byte `0xCC` -> return `19`
  - nguoc lai -> return `55`

<img width="635" height="303" alt="ida_bSLBGBnYhr" src="https://github.com/user-attachments/assets/9b90983c-808c-41b8-818d-5ec8c9ca7bad" />

#### c) Gia tri thuc te (xac nhan bang py_eval trong IDA)
- Cho `_main`:
  - do dai den `0xC3`: `287`
  - co `0xCC` (offset 46) -> `sub_4010C0(main, 287) = 19`
- Cho `sub_401120`:
  - do dai den `0xC3`: `476`
  - khong co `0xCC` -> `sub_4010C0(sub_401120, 476) = 55`

=> Key seed:
- `v7_initial = 19 ^ 0xDEADBEEF = 0xDEADBEFC`
- Trong `sub_401120`: `*a3 = *a3 + 55`
- `v7_final = 0xDEADBEFC + 0x37 = 0xDEADBF33`
- Little-endian key bytes dung trong RC4 KSA:
  - `33 BF AD DE`

### 3.4 `sub_401120` la RC4

Decompile cho thay du mau RC4:

1. Khoi tao S-box 256 phan tu.
2. KSA:
   - S[i] swap theo key byte `*((BYTE*)a3 + i % n4)` voi `n4 = 4`.
3. PRGA:
   - sinh keystream tu S-box.
   - `out[k] = keystream ^ Buffer[k]`.

Trong `_main`:
- `n13 = 13` -> ma hoa 13 byte dau cua input.
- output dat vao `v9` roi `memcmp` voi target.

### 3.5 Cach giai

- Vi RC4 doi xung, decrypt cung chinh la RC4 voi cung key.
- Ta lay:
  - ciphertext: `7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4`
  - key: `33 BF AD DE`
- RC4 decrypt -> plain:
  - `D1t_m3_H4_N41`

### 3.6 PoC solve

```python
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

cipher = bytes.fromhex("7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4")
key = bytes.fromhex("33 BF AD DE")
plain = rc4(key, cipher).decode()

print("plain:", plain)
print("flag :", f"Flag{{{plain}}}")
```

### 3.7 Ket qua

- Plain pass: `D1t_m3_H4_N41`
- Flag: `Flag{D1t_m3_H4_N41}`

## 4) n1gg4.exe

### 4.1 Phan tich dau bai

- Mau ban dau dong goi (UPX loi header), nen can dump/fix IAT roi moi doc de.
- Sau khi clean file va xem duoc logic:
  - Co vong lap ngoai xu ly tung byte.
  - Co vong lap trong XOR theo key pattern, phu thuoc `dword_403710`.
  - Sau do co buoc `neg al` (dao dau byte).

- Dieu quan trong:
  - `dword_403710 = 0`
  - => vong XOR trong khong chay.
  - => transform con lai chu yeu la `byte = (-byte) & 0xFF`.

### 4.2 Van de

- Du lieu plaintext bi cat thanh nhieu segment o nhieu dia chi.
- Neu decrypt tung doan khong dung thu tu se ra string "dung ky tu nhung sai nghia".

### 4.3 Cach handle

1. Trich tung segment enc.
2. Moi byte ap dung `(-b) & 0xFF`.
3. Ghep theo thu tu dung de ra cau pass hoan chinh.

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

# Thu tu ghep dung theo flow
full = p2 + p3 + p4 + p1
print("full:", full)
```

### 4.5 Ket qua

- Recover duoc chuoi anti-debug day du de nhap vao chuong trinh.
- Cac segment giai ra (de doi chieu):
  - `St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3`
  - `NtQu3ry1nf0rm@t10nPr0(355`
  - `R@!s33xc3pt!on`
  - `D3bugPr1v1l3g3`

---

## 5) antidebug3.exe

### 5.1 Phan tich dau bai

- `_main` (`0x4015B0`) khong xu ly input theo flow thong thuong. No:
  - `SetUnhandledExceptionFilter(TopLevelExceptionFilter)`
  - Co tinh tao exception (chia 0 / software interrupt) de nhay vao handler.
- Vi vay, flow chinh cua chall nam trong `TopLevelExceptionFilter` (`0x4014C0`), khong nam o phan main decompile "dep".

- Doan dau `TopLevelExceptionFilter` co anti-disasm:
  - `jz` + `jnz` deu nhay vao giua instruction (kieu jump-into-middle).
  - Neu khong undefine/redefine code, IDA se tao ra call rac.
  - Decode lai dung thi thay:
    - `byte_404082 = BeingDebugged ^ 0xAB`
    - `byte_404083 = v3 ^ 0xCD` (v3 tu check PEB/NtGlobalFlag-like)

- Ham compare cuoi cung la `sub_401100`:
  - So sanh `byte_404640[i]` voi `byte_404118[i]` trong 100 byte.
  - In `Status: x/100`.
  - Dung 100/100 thi in `You got it! flag: kcsc{%s}` voi `%s = unk_404560`.

### 5.2 Van de

- Kho nhat la bai nay khong co "1 ham ma hoa" don le, ma la pipeline nhieu block, moi block xu ly 1 doan offset.
- `sub_401400` scan opcode `0xCC` trong vung `sub_401330`:
  - `return i_1 - i + 0xBEEF`.
  - Chay thuong: khong co `0xCC` => ket qua dung bang `0xBEEF`.
  - Neu dat software breakpoint (patch `0xCC`) vao vung bi quet, gia tri nay doi va lam huong xu ly sai.
- 1 block khac phu thuoc `BeingDebugged`:
  - Chay thuong: xor voi `0xAB`.
  - Dang debug: xor voi `0xAA`.

### 5.3 Tach block transform

`TopLevelExceptionFilter` copy input vao `0x404560`, tinh key, roi goi `sub_401460(0x404652)`.
Tu disasm/pseudocode co the tach duoc block theo offset trong buffer 100 byte nhu sau:

1. Offset `0..16`: `buf[i] ^= 1`
2. Offset `18..25`: `buf[i] ^= (BeingDebugged ^ 0xAB)`  
   - run binh thuong => `BeingDebugged = 0` => xor `0xAB`
3. Offset `27..38`:  
   `out = (0xCD + i) ^ (((x << 1) & 0xFF) | 1)`  
   - dao nguoc can brute-force trong bo ky tu hop ly
4. Offset `40..57`: xor word voi `0xBEEF`
5. Offset `59..63`: `ror8(buf[i], i)` -> dao nguoc bang `rol8`
6. Offset `65..68`: xor dword `0xC0FE1337`
7. Offset `70..99`: xor-chain lien tiep (`buf[i] ^= buf[i-1]`)  
   - dao nguoc phai di nguoc tu cuoi ve dau.

### 5.4 Cach handle

- Lay 100-byte target o `0x404118` (chuoi bat dau bang `74 6F 69 35 4F 65 ...`).
- Reverse theo thu tu nguoc: block `7 -> 1`.
- O block 3, nghich dao khong 1-1 neu khong rang buoc ky tu, nen brute-force tren alphabet:
  - `[a-zA-Z0-9_]`
- Chon scenario chay thuong (`BeingDebugged=0`) de dung key `0xAB` cho block 2.

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

### 5.6 Ket qua

- Chuoi recover:
  - `unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===`
- Flag:
  - `kcsc{unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===}`

---

## 6) harder-medium-antidebug.exe

### 6.1 Phan tich dau bai

- `main` cuc ngan:
  - `int3`
  - `call off_7FF7630C83B0`
  - `call main` (de quy tiep)
- Nghia la moi vong lap se co 1 `int3`, va logic that su nam trong exception flow.

- Handler chinh: `sub_7FF7630BC7C0` (dang ky bang `RtlAddVectoredExceptionHandler` trong `sub_7FF7630BC950`).
- Handler chi nhan `EXCEPTION_BREAKPOINT (0x80000003)`, roi:
  1. Lay index tiep theo tu `dword_7FF7630C5740[n2831++]`
  2. Lay function pointer `off_7FF7630BE2D0[index]`
  3. `VirtualProtect` 12 bytes o thunk `off_7FF7630C83B0`
  4. Patch thunk thanh `48 B8 <addr> FF E0` (`mov rax, addr ; jmp rax`)
  5. Return `-1` de tiep tuc execution

- Tuc la chall nay dung kieu exception-dispatch VM: moi lan `int3` se chay 1 ham trong bang da shuffle.

### 6.2 Van de

- Co 2 lop anti-debug:
  1. Dieu khien flow bang exception + runtime code patch
  2. Check `IsDebuggerPresent` de doi nhanh

- `dword_7FF7630C5740` khong co thu tu co dinh trong file, ma duoc tao runtime:
  - `sub_7FF7630BCA20`: `arr[i] = i`, `srand(0x539)`
  - `sub_7FF7630BC9D0`: Fisher-Yates shuffle bang `rand()`
- Dat software breakpoint bo bua rat de lam sai flow.

### 6.3 Dung flow thuc te bang IDA-MCP

- Dung `py_eval` mo phong lai shuffle (seed `0x539`) de lay thu tu ham.
- Cac moc quan trong trong sequence:
  - `1546`: `IsDebuggerPresent` -> `dword_7FF7630C83B8`
  - `1693..1695`: `LoadLibraryA("cryptsp.dll" / "cryptbase.dll" / "user32.dll")`
  - `1696`: khoi tao buffer/descriptor
  - `1697,1698`: `GetStdHandle(-10/-11)`
  - `1699`: in `"Enter password: "`
  - `1700`: `ReadConsoleA` doc 8 bytes vao `qword_7FF7630C5710`
  - `1779`: neu debug -> `ExitProcess` (`sub_7FF7630BC7A0`)
  - `1780..1787`: nhom ham crypto
  - `2829`: compare (`sub_7FF7630BC6C0`)
  - `2830`: in ket qua (`sub_7FF7630BC710`)

- `sub_7FF7630BC6C0` con co nhanh debug:
  - Neu debug, goi them 1 lan `SystemFunction002` truoc khi compare.

### 6.4 Tach crypto chain va key material

- Resolve hash trong `sub_7FF7630B1050` cho thay:
  - `sub_7FF7630BC680` -> `SystemFunction033` (RC4)
  - `sub_7FF7630BC6A0` -> `SystemFunction002` (DES block transform)

- Data:
  - Key material tai `0x7FF7630C5078`: `"12345678"`
  - Target tai `0x7FF7630C5080`: `24 28 14 4A 11 A0 7F E4`

- Thu tu crypto thuc te (slot `1780..1787`):
  - `RC4, DES, RC4, RC4, DES, DES, DES, RC4`
  - Hai lan RC4 lien tiep giua chain triet tieu nhau.
  - Chain rut gon:
    - `C = RC4(DES(DES(DES(DES(RC4(P))))))`

- Voi `SystemFunction002`, key DES hieu dung la 56-bit packed tu 7 byte dau cua `"12345678"`:
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

### 6.6 Ket qua

- Password recover: `debugger`
- Chay binary va nhap `debugger` -> `Correct!`

---
