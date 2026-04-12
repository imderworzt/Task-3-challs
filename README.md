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


### ThitNhi.exe

Khi nhìn vào mã giả hàm main ta thấy một mảng dữ liệu:
```
  v11[0] = 125;
  v11[1] = 8;
  v11[2] = -19;
  v11[3] = 71;
  v11[4] = -27;
  v11[5] = 0;
  v11[6] = -120;
  v11[7] = 58;
  v11[8] = 122;
  v11[9] = 54;
  v11[10] = 2;
  v11[11] = 41;
  v11[12] = -28;
  v11[13] = 0;
```

Khi đổi từ hệ thập phân sang hệ hexa ta thu được đoạn hex sau: 7D 08 ED 47 E5 00 88 3A 7A 36 02 29 E4 (Bỏ giá trị 00 ở cuối)

Nhìn vào hàm sub_401120 ta thấy nội dung:
```
unsigned int __cdecl sub_401120(char *Buffer, int n13, unsigned int *a3, int n4, _DWORD *a5)
{
  int v5; // eax
  unsigned int result; // eax
  _BYTE v7[512]; // [esp+0h] [ebp-21Ch]
  int v8; // [esp+200h] [ebp-1Ch]
  int k; // [esp+204h] [ebp-18h]
  int v10; // [esp+208h] [ebp-14h]
  int j; // [esp+20Ch] [ebp-10h]
  int i; // [esp+210h] [ebp-Ch]
  int v13; // [esp+214h] [ebp-8h]
  char v14; // [esp+21Bh] [ebp-1h]

  v13 = 0;
  v8 = 0;
  v10 = 0;
  v5 = sub_401080((int (__cdecl *)(int, const char **, const char **))sub_401120);
  result = *a3 + sub_4010C0((int (__cdecl *)(int, const char **, const char **))sub_401120, v5);
  *a3 = result;
  for ( i = 0; i < 256; ++i )
  {
    v7[i + 256] = i;
    v7[i] = *((_BYTE *)a3 + i % n4);
    result = i + 1;
  }
  for ( j = 0; j < 256; ++j )
  {
    v13 = ((unsigned __int8)v7[j] + v13 + (unsigned __int8)v7[j + 256]) % 256;
    v14 = v7[v13 + 256];
    v7[v13 + 256] = v7[j + 256];
    v7[j + 256] = v14;
    result = j + 1;
  }
  v13 = 0;
  for ( k = 0; k < n13; ++k )
  {
    v10 = (v10 + 1) % 256;
    v13 = (v13 + (unsigned __int8)v7[v10 + 256]) % 256;
    v14 = v7[v13 + 256];
    v7[v13 + 256] = v7[v10 + 256];
    v7[v10 + 256] = v14;
    v8 = ((unsigned __int8)v7[v13 + 256] + (unsigned __int8)v7[v10 + 256]) % 256;
    *((_BYTE *)a5 + k) = v7[v8 + 256] ^ Buffer[k];
    result = k + 1;
  }
  return result;
}
```

Đây là hàm mã hóa RC4 với đầu vào là đoạn Buffer, key là biến v7

Vậy ta chỉ cần tìm được giá trị v7 là có thể tìm lại được đoạn ban đầu

Vậy v7 tìm như thế nào?

Trước hết, ta vào hàm sub_4010C0, là hàm được gọi với kết quả return vào biến v7:
```
int __cdecl sub_4010C0(int (__cdecl *_main)(int argc, const char **argv, const char **envp), unsigned int i_1)
{
  unsigned int i; // [esp+4h] [ebp-8h]

  for ( i = 0; i < i_1; ++i )
  {
    if ( *((unsigned __int8 *)_main + i) == 204 )
      return 19;
  }
  return 55;
}
```
Ta thấy 204 đổi sang hex là 0xCC. Về cơ bản thì hàm này có nhiệm vụ là quét 1 hàm được chỉ thị, nếu trong hàm này có chứa opcode CC bằng bất cứ lí do nào, nó sẽ trả vê 19. Còn không thì trả về 55

Ta chọn Option -> General và setting như sau (để Number of opcodes lớn hơn 0)

<img width="597" height="563" alt="ida_f6oVOq8yDJ" src="https://github.com/user-attachments/assets/01a17eb2-40b9-40e8-bd00-85ea4b21e25a" />

Sử dụng text view, ta quan sát được có 1 opcode CC ở dòng

<img width="1275" height="731" alt="ida_zIOCCh26DW" src="https://github.com/user-attachments/assets/e21129a7-9c7c-421e-9e7a-c4db059aa20a" />

```
.text:004013FE 8D 55 CC                       lea     edx, [ebp+Buffer]
```

Nghĩa là dù có đặt breakpoint ở hàm main hay không thì giá trị vẫn sẽ là 19 -> 0x13 -> v7 khi đưa vào hàm sẽ có giá trị là 0x13 ^ 0xDEADBEEF

Tuy nhiên ở hàm RC4 ban nãy, sub_4010C0 lại được gọi để check chính hàm RC4 này
```
result = *a3 + sub_4010C0((int (__cdecl *)(int, const char **, const char **))sub_401120, v5);
```

Và nếu ta sử dụng text view kiểm tra hàm RC4, ta không thấy opcode CC nào cả -> giá trị hàm trả về là 55 hay 0x37

Vậy là key trong hàm RC4 này sẽ là 0x13 ^ 0xDEADBEEF + 0x37 = 0x33BFADDE

Giờ ta đã có key, và kết quả cần mã hóa, ta lên cryptii.com để decrypt như sau

<img width="1920" height="997" alt="brave_bGjTQy6H6h" src="https://github.com/user-attachments/assets/475656c5-c7f6-453d-a26c-101a9d020861" />

<img width="960" height="480" alt="cmd_I18MIziOFi" src="https://github.com/user-attachments/assets/2777a5d5-1174-4857-8c8f-e63044464b96" />

Giải thành công, flag là: Flag{D1t_m3_H4_N41}


### n1gg4.exe

Khi mở bài này trong ida, ta thấy đây là 1 bài được đóng gói UPX, tuy nhiên khi sử dụng UPX để giải nén thì bị báo header sai, vì vậy chúng ta có thể dùng Scylla để fix lại file.

Sau đó, mở file dump đấy lên IDA

<img width="1920" height="1080" alt="ida_o3cUQNFVmd" src="https://github.com/user-attachments/assets/a661efb9-fb63-4a99-85ac-04a536c89f94" />

Vẫn có một số chỗ là các đoạn byte có thể sử dụng U và C để xem nó có phải là code được ẩn hay không (chắc vậy)

Vậy chương trình này làm gì?

Khi bạn nhập chuỗi plaintext, nó sẽ so sánh với chuỗi text sau khi được decrypt tại loc_40110C

Tại loc_40110C:                        
```
UPX0:0040110C                 xor     al, [ebx]
UPX0:0040110E                 inc     edx
UPX0:0040110F                 cmp     edx, dword_403710
UPX0:00401115                 jb      short loc_40110C
UPX0:00401117                 neg     al
UPX0:00401119                 stosb
UPX0:0040111A                 loop    loc_4010FC
UPX0:0040111C                 popa
UPX0:0040111D                 retn
```

Viết lại pseudocode có thể ra như sau:
```
def decrypt_function():
     for i in range(ecx):                    # Outer: decrypt ecx bytes
         byte = encrypted_data[i]

         for j in range(dword_403710):       # Inner: XOR với key pattern
             byte ^= key[j]

         byte = (-byte) & 0xFF               # Negate
         output_buffer[i] = byte
```

Nó thực hiện:
  - XOR loop (inner): XOR lặp lại dword_403710 lần
  - Negation: Sau khi XOR xong, negate byte
  - Store: STOSB lưu vào destination buffer
  - Repeat: LOOP lặp cho tất cả bytes (ecx lần)

Chúng ta tìm đến dword_403710

```
UPX0:00403710 dword_403710    dd 0                    ; DATA XREF: UPX0:0040110F↑r
UPX0:00403710                                         ; UPX0:004013B3↑r ...
```

Vì giá trị của nó bằng 0 -> ta thấy hàm này thực ra chỉ thực hiện 2 dòng cuối trong pseudocode

Đoạn plaintext thật sự được ghép từ 4 đoạn được decrypt bao gồm:

Đoạn 1:
004010C0  00 AD 8C C0 9D 95 AC CF  93 CD BD BD AD CD 94 9A
004010D0  D3 B0 CD BE BA CF 92 9C  A9 CF 92 9C D0 89 B8 CF
004010E0  9C CF 92 99 C0 92 8C CF  D3 AE CD 8A CD 8E 8D CD

Đoạn 2: 
004011E0                    B2 8C  AF 8B CD 8E 87 CF 92 9A (còn 6 byte đằng trước không thuộc đoạn cần sử dụng)
004011F0  D0 8E 93 C0 8C CF D0 92  B0 8E D0 D8 CD CB CB    (còn 1 byte đằng sau không thuộc đoạn cần sử dụng)

Đoạn 3: 
0x40130B  AE C0 DF 8D CD CD 88 9D CD 90 8C DF 91 92

Đoạn 4: 
0x401386 BC CD  9E 8B 99 B0 8E CF 8A CF 94 CD 99 CD

Và 4 đoạn này khi decrypt sẽ tạo được 4 đoạn plaintext sau:
Đoạn 1: St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3
Đoạn 2: NtQu3ry1nf0rm@t10nPr0(355
Đoạn 3: R@!s33xc3pt!on
Đoạn 4: D3bugPr1v1l3g3

Ghép lại ta có: NtQu3ry1nf0rm@t10nPr0(355R@!s33xc3pt!onD3bugPr1v1l3g3St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3

Nhập vào phần mềm và nailed it!

<img width="1258" height="384" alt="Discord_Kkg06pRRw7" src="https://github.com/user-attachments/assets/dc96abe5-b01b-40f8-9d8f-5c10f3273fcf" />

### anti3.exe
