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
```
004010C0  00 AD 8C C0 9D 95 AC CF  93 CD BD BD AD CD 94 9A
004010D0  D3 B0 CD BE BA CF 92 9C  A9 CF 92 9C D0 89 B8 CF
004010E0  9C CF 92 99 C0 92 8C CF  D3 AE CD 8A CD 8E 8D CD
```

Đoạn 2: 
```
004011E0                    B2 8C  AF 8B CD 8E 87 CF 92 9A (còn 6 byte đằng trước không thuộc đoạn cần sử dụng)
004011F0  D0 8E 93 C0 8C CF D0 92  B0 8E D0 D8 CD CB CB    (còn 1 byte đằng sau không thuộc đoạn cần sử dụng)
```

Đoạn 3: 
```
0x40130B  AE C0 DF 8D CD CD 88 9D CD 90 8C DF 91 92
```

Đoạn 4: 
```
0x401386 BC CD  9E 8B 99 B0 8E CF 8A CF 94 CD 99 CD
```

Và 4 đoạn này khi decrypt sẽ tạo được 4 đoạn plaintext sau:

Đoạn 1: St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3

Đoạn 2: NtQu3ry1nf0rm@t10nPr0(355

Đoạn 3: R@!s33xc3pt!on

Đoạn 4: D3bugPr1v1l3g3

Ghép lại ta có: NtQu3ry1nf0rm@t10nPr0(355R@!s33xc3pt!onD3bugPr1v1l3g3St@ckT1m3CCS3lf-P3BF1ndW1nd0wH1d1ng@nt1-R3v3rs3

Nhập vào phần mềm và nailed it!

<img width="1258" height="384" alt="Discord_Kkg06pRRw7" src="https://github.com/user-attachments/assets/dc96abe5-b01b-40f8-9d8f-5c10f3273fcf" />

### antidebug3.exe

Bài này anti debug sử dụng exception flow. Flow của chương trình sẽ khác nếu debug và chạy thường

<img width="459" height="659" alt="ida_9e0pkbyGHs" src="https://github.com/user-attachments/assets/5aeffe4b-9d87-4715-af21-5b37637e2052" />

Hàm main này cố tình tạo phép tính chia cho 0, software interupt gây exception

Logic thật sự của chương trình nằm ở Exception:

```
text:004014C0                TopLevelExceptionFilter:                ; DATA XREF: _main+6↓o
.text:004014C0 55                             push    ebp
.text:004014C1 8B EC                          mov     ebp, esp
.text:004014C3 83 EC 10                       sub     esp, 10h
.text:004014C6 53                             push    ebx
.text:004014C7 56                             push    esi
.text:004014C8 57                             push    edi
.text:004014C9 74 03                          jz      short near ptr loc_4014CD+1
.text:004014CB 75 01                          jnz     short near ptr loc_4014CD+1
.text:004014CD
.text:004014CD                loc_4014CD:                             ; CODE XREF: .text:004014C9↑j
.text:004014CD                                                        ; .text:004014CB↑j
.text:004014CD E8 C7 45 F8 00                 call    near ptr 1385A99h
.text:004014CD                ; ---------------------------------------------------------------------------
.text:004014D2 00 00                          dw 0
.text:004014D4                ; ---------------------------------------------------------------------------
.text:004014D4 00 64 A1 30                    add     [ecx+30h], ah
.text:004014D4                ; ---------------------------------------------------------------------------
.text:004014D8 00                             db    0
.text:004014D9 00                             db    0
.text:004014DA                ; ---------------------------------------------------------------------------
.text:004014DA 00 89 45 F0 8B                 add     [ecx+4D8BF045h], cl
.text:004014DA 4D
.text:004014E0 F0 81 C1 C0 BF                 lock add ecx, 0BFC0h
.text:004014E0 00 00
.text:004014E7 89 4D F8                       mov     [ebp-8], ecx
.text:004014EA 74 13                          jz      short loc_4014FF
.text:004014EC 8B 55 F8                       mov     edx, [ebp-8]
.text:004014EF 8B 02                          mov     eax, [edx]
.text:004014F1 83 E0 70                       and     eax, 70h
.text:004014F4 74 09                          jz      short loc_4014FF
.text:004014F6 C7 45 F4 01 00                 mov     dword ptr [ebp-0Ch], 1
.text:004014F6 00 00
.text:004014FD EB 07                          jmp     short loc_401506
.text:004014FF                ; ---------------------------------------------------------------------------
.text:004014FF
.text:004014FF                loc_4014FF:                             ; CODE XREF: .text:004014EA↑j
.text:004014FF                                                        ; .text:004014F4↑j
.text:004014FF C7 45 F4 00 00                 mov     dword ptr [ebp-0Ch], 0
.text:004014FF 00 00
.text:00401506
.text:00401506                loc_401506:                             ; CODE XREF: .text:004014FD↑j
.text:00401506 8B 4D F4                       mov     ecx, [ebp-0Ch]
.text:00401509 81 F1 CD 00 00                 xor     ecx, 0CDh
.text:00401509 00
.text:0040150F 88 0D 83 40 40                 mov     byte_404083, cl
.text:0040150F 00
.text:00401515 8B 55 F0                       mov     edx, [ebp-10h]
.text:00401518 0F B6 42 02                    movzx   eax, byte ptr [edx+2]
.text:0040151C 35 AB 00 00 00                 xor     eax, 0ABh
.text:00401521 A2 82 40 40 00                 mov     byte_404082, al
.text:00401526 68 FC 40 40 00                 push    offset aEnterFlag ; "Enter flag: "
.text:0040152B E8 20 FB FF FF                 call    sub_401050
.text:00401530 83 C4 04                       add     esp, 4
.text:00401533 68 40 46 40 00                 push    offset byte_404640
.text:00401538 68 0C 41 40 00                 push    offset aS       ; "%s[\n]"
.text:0040153D E8 7E FB FF FF                 call    sub_4010C0
.text:00401542 83 C4 08                       add     esp, 8
.text:00401545 6A 64                          push    64h ; 'd'
.text:00401547 68 40 46 40 00                 push    offset byte_404640
.text:0040154C 68 60 45 40 00                 push    offset unk_404560
.text:00401551 FF 15 38 30 40                 call    ds:memcpy
.text:00401551 00
.text:00401557 83 C4 0C                       add     esp, 0Ch
.text:0040155A E8 A1 FE FF FF                 call    sub_401400
.text:0040155F A3 14 41 40 00                 mov     dword_404114, eax
.text:00401564 C7 45 FC 00 00                 mov     dword ptr [ebp-4], 0
.text:00401564 00 00
.text:0040156B EB 09                          jmp     short loc_401576
.text:0040156D                ; ---------------------------------------------------------------------------
.text:0040156D
.text:0040156D                loc_40156D:                             ; CODE XREF: .text:00401592↓j
.text:0040156D 8B 4D FC                       mov     ecx, [ebp-4]
.text:00401570 83 C1 01                       add     ecx, 1
.text:00401573 89 4D FC                       mov     [ebp-4], ecx
.text:00401576
.text:00401576                loc_401576:                             ; CODE XREF: .text:0040156B↑j
.text:00401576 83 7D FC 11                    cmp     dword ptr [ebp-4], 11h
.text:0040157A 7D 18                          jge     short loc_401594
.text:0040157C 8B 55 FC                       mov     edx, [ebp-4]
.text:0040157F 0F BE 82 40 46                 movsx   eax, byte_404640[edx]
.text:0040157F 40 00
.text:00401586 83 F0 01                       xor     eax, 1
.text:00401589 8B 4D FC                       mov     ecx, [ebp-4]
.text:0040158C 88 81 40 46 40                 mov     byte_404640[ecx], al
.text:0040158C 00
.text:00401592 EB D9                          jmp     short loc_40156D
.text:00401594                ; ---------------------------------------------------------------------------
.text:00401594
.text:00401594                loc_401594:                             ; CODE XREF: .text:0040157A↑j
.text:00401594 68 52 46 40 00                 push    offset unk_404652
.text:00401599 E8 C2 FE FF FF                 call    sub_401460
.text:0040159E 83 C4 04                       add     esp, 4
.text:004015A1 33 C0                          xor     eax, eax
.text:004015A3 5F                             pop     edi
.text:004015A4 5E                             pop     esi
.text:004015A5 5B                             pop     ebx
.text:004015A6 8B E5                          mov     esp, ebp
.text:004015A8 5D                             pop     ebp
.text:004015A9 C2 04 00                       retn    4
```

Trong này có gọi hàm sub_401400 đi tìm 0xCC

```
int sub_401400()
{
  unsigned int i_1; // [esp+4h] [ebp-8h]
  unsigned int i; // [esp+8h] [ebp-4h]

  i_1 = (char *)sub_4013F0 - (char *)&loc_401330 - 16;
  for ( i = 0; i < i_1 && *((unsigned __int8 *)&loc_401330 + i) != 204; ++i )
    ;
  return i_1 - i + 48879;
}
```

Và như bạn thấy ở trên, số opcode 0xCC trong hàm đúng bằng khả năng tôi qua môn thể chất: HOÀN TOÀN KHÔNG CÓ

Vì vậy, nếu bạn đặt bp ở đây, có thể sẽ bị quét và điều chỉnh flow khác với flow cần đi

Đọc pseudocode hàm so sánh:
```
int sub_401100()
{
  int result; // eax
  char v1[4]; // [esp+0h] [ebp-Ch]
  int i; // [esp+4h] [ebp-8h]

  *(_DWORD *)v1 = 0;
  for ( i = 0; i < 100; ++i )
  {
    if ( byte_404640[i] == byte_404118[i] )
      ++*(_DWORD *)v1;
  }
  result = sub_401050(Format, v1[0]);
  if ( *(_DWORD *)v1 == 100 )
    return sub_401050(aYouGotItFlagKc, (char)&unk_404560);
  return result;
}
```

Ta thấy:
`target_buf' chứa 100 bytes
?/100 trong output là số bytes chính xác

Logic mã hóa của bài này nằm trong hàm sub_401460 và các hàm được gọi sau đấy có thể giải thích như sau:
```
.text:00401460                ; int __cdecl sub_401460(int)
.text:00401460                sub_401460      proc near               ; CODE XREF: .text:00401599↓p
.text:00401460
.text:00401460                var_4           = dword ptr -4
.text:00401460                arg_0           = dword ptr  8
.text:00401460
.text:00401460 55                             push    ebp
.text:00401461 8B EC                          mov     ebp, esp
.text:00401463 51                             push    ecx
.text:00401464 8D 45 08                       lea     eax, [ebp+arg_0]
.text:00401467 50                             push    eax
.text:00401468 E8 C3 FE FF FF                 call    loc_401330
.text:0040146D 83 C4 04                       add     esp, 4
.text:00401470 C7 45 FC 00 00                 mov     [ebp+var_4], 0
.text:00401470 00 00
.text:00401477 EB 09                          jmp     short loc_401482
.text:00401479                ; ---------------------------------------------------------------------------
.text:00401479
.text:00401479                loc_401479:                             ; CODE XREF: sub_401460+42↓j
.text:00401479 8B 4D FC                       mov     ecx, [ebp+var_4]
.text:0040147C 83 C1 01                       add     ecx, 1
.text:0040147F 89 4D FC                       mov     [ebp+var_4], ecx
.text:00401482
.text:00401482                loc_401482:                             ; CODE XREF: sub_401460+17↑j
.text:00401482 83 7D FC 09                    cmp     [ebp+var_4], 9
.text:00401486 7D 1C                          jge     short loc_4014A4
.text:00401488 8B 55 FC                       mov     edx, [ebp+var_4]
.text:0040148B 8B 45 08                       mov     eax, [ebp+arg_0]
.text:0040148E 0F B7 0C 50                    movzx   ecx, word ptr [eax+edx*2]
.text:00401492 33 0D 14 41 40                 xor     ecx, dword_404114
.text:00401492 00
.text:00401498 8B 55 FC                       mov     edx, [ebp+var_4]
.text:0040149B 8B 45 08                       mov     eax, [ebp+arg_0]
.text:0040149E 66 89 0C 50                    mov     [eax+edx*2], cx
.text:004014A2 EB D5                          jmp     short loc_401479
.text:004014A4                ; ---------------------------------------------------------------------------
.text:004014A4
.text:004014A4                loc_4014A4:                             ; CODE XREF: sub_401460+26↑j
.text:004014A4 8B 4D 08                       mov     ecx, [ebp+arg_0]
.text:004014A7 83 C1 13                       add     ecx, 13h
.text:004014AA 51                             push    ecx
.text:004014AB E8 20 FD FF FF                 call    sub_4011D0
.text:004014B0 83 C4 04                       add     esp, 4
.text:004014B3 8B E5                          mov     esp, ebp
.text:004014B5 5D                             pop     ebp
.text:004014B6 C3                             retn
.text:004014B6                sub_401460      endp
.text:004014B6
```

- 17 bytes đầu: xor với 1

- Bytes thứ 19 - 26: xor với (BeingDebugged ^ 0xAB). Mà giá trị của BeingDebugged là 0 hoặc 1 -> Nếu chạy bình thường thì giá trị này bằng 0
    -> Các bytes này đúng ra sẽ được xor với 0 ^ 0xAB = 0xAB. Nhưng nếu quét được debug thì nó sẽ được xor với 1 ^ 0xAB = 0xAA

- Bytes thứ 28 - 39: out[i] = (0xCD + i) ^ (((x << 1) & 0xff) | 1)
    -> Đảo ngược lại sẽ là: z = out[i] ^ (0xCD + i)  -> Cần bruteforce tìm x thỏa mãn (((x << 1) & 0xff) | 1) == z và giá trị tương đương với các kí tự alphabet

- Bytes thứ 41 - 58: xor với 0xBEEF

- Bytes thứ 60 - 64: buf[i] = ror8(buf[i], i) -> đảo ngược sẽ là buf[i] = ror18(buf[i], i)

- Bytes thứ 66 - 69: xor với 0xC0FE1337

- Bytes thứ 71 - 100: Như các bạn thấy ở đây có 30 bytes, và vòng lặp của khúc này là xor byte thứ i với bytes thứ i - 1 (với i < 0)

Vào hex-view ta thấy đoạn hex sau:

<img width="1549" height="773" alt="ida_BHh9oqlaPu" src="https://github.com/user-attachments/assets/1d6bbe50-62ec-4ae0-ba3a-23ed4294e9af" />

Ta thấy có 1 string: toi5Oem22yB2qUh1o. Khả năng chuỗi byte encrypt bắt đầu từ đây, vậy 100 bytes này là: 

```
                         74 6F 69 35 4F 65 6D 32
32 79 42 32 71 55 68 31  6F 5F DB CE C9 EF CE C9
FE 92 5F 10 27 BC 09 0E  17 BA 4D 18 0F BE AB 5F
9C 8E A9 89 98 8A 9D 8D  D7 CC DC 8A A4 CE DF 8F
81 89 5F 69 37 1D 46 46  5F 5E 7D 8A F3 5F 59 01
57 67 06 41 78 01 65 2D  7B 0E 57 03 68 5D 07 69
23 55 37 60 14 7E 1D 2F  62 5F 62 5F
```

Ta viết script giải (with the help of AI)

```
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
  
def ror8(x, n):  
    n &= 7  
    return ((x >> n) | ((x << (8 - n)) & 0xff)) & 0xff  
  
def rol8(x, n):  
    n &= 7  
    return ((x << n) | (x >> (8 - n))) & 0xff  
  
def recover_inner(target: bytes) -> bytes:  
    buf = bytearray(target)  
  
    # block 6: reverse xor-chain, offset 70..99  
    for i in range(29, 0, -1):  
        buf[70 + i] ^= buf[70 + i - 1]  
  
    # block 5: reverse int3 block, offset 65..68  
    d = struct.unpack_from("<I", buf, 65)[0] ^ 0xC0FE1337  
    struct.pack_into("<I", buf, 65, d)  
  
    # block 4: reverse int2d block, offset 59..63  
    for i in range(5):  
        buf[59 + i] = rol8(buf[59 + i], i)  
  
    # block 3: reverse 0xBEEF word xor, offset 40..57  
    for i in range(9):  
        idx = 40 + i * 2  
        w = (buf[idx] | (buf[idx + 1] << 8)) ^ 0xBEEF  
        buf[idx] = w & 0xff  
        buf[idx + 1] = (w >> 8) & 0xff  
  
    # block 2: reverse ((x << 1) | 1) xor key, offset 27..38  
    for i in range(12):  
        idx = 27 + i  
        z = buf[idx] ^ ((0xCD + i) & 0xff)  
        cand = [c for c in ALPHABET if ((((c << 1) & 0xff) | 1) == z)]  
        if len(cand) != 1:  
            raise ValueError(f"ambiguous inverse at idx={idx}: {cand}")  
        buf[idx] = cand[0]  
  
    # block 1: reverse xor 0xAB, offset 18..25  
    for i in range(8):  
        buf[18 + i] ^= 0xAB  
  
    # block 0: reverse xor 1, offset 0..16  
    for i in range(17):  
        buf[i] ^= 1  
  
    return bytes(buf)  
  
print(recover_inner(TARGET).decode())

```

Và output thu được là: unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===

<img width="1549" height="1034" alt="RvRvpnGui_rAsvNE7skS" src="https://github.com/user-attachments/assets/b846232c-9374-43cb-9d81-5316c964b701" />

Chạy chương trình: 

<img width="984" height="509" alt="Code_oWRmaxWGOL" src="https://github.com/user-attachments/assets/83f3b0c9-88f7-4988-a613-d35cfb85b8ce" />

### harder-medium-antidebug.exe:

Đặt breakpoint vào những chỗ sau:

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/818ba728-f43a-4974-9cef-07ac4cbfad67" />

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ddeff04c-809c-43ce-b966-72bba1563738" />

<img width="1534" height="524" alt="ida_fKP5qajXhC" src="https://github.com/user-attachments/assets/a48306bf-d1eb-4d57-b7f0-29bbba6f4b36" />

<img width="1468" height="365" alt="ida_tz380qkPR8" src="https://github.com/user-attachments/assets/6aa23205-31ac-4cc8-9319-86765f76c7b9" />

<img width="1093" height="277" alt="ida_ZoKK8yYoOZ" src="https://github.com/user-attachments/assets/ae0c585e-5351-46c1-9632-164d6fc71057" />

<img width="1536" height="755" alt="ida_KNdS0Ki9Rq" src="https://github.com/user-attachments/assets/2127c09b-ee02-4b46-95e3-f9090134ac6d" />

Fix lỗi 0x8000003:

Debugger -> Debugger Options -> Edit Exceptions -> Chọn 8000003 -> Bỏ tick suspend và tick vào pass to aplication

Giờ debug thôi. Từ đoạn này sửa EAX thành 0

<img width="1920" height="1080" alt="ida_DwnBAO1eNV" src="https://github.com/user-attachments/assets/64686afd-d79b-4830-8a64-a3f8d38b7bdb" />

Qua đoạn này nhập trước 12345678

<img width="1920" height="1080" alt="ida_7MI4i3IVN5" src="https://github.com/user-attachments/assets/60fcbb71-6556-460f-9598-213a86f7c0dc" />

Đến 2 đoạn này ta thấy 2 hàm ở EAX trỏ đến là SystemFunction002 (F) và SystemFunction032 (G)

<img width="1920" height="1080" alt="ida_BvL6mLqG0g" src="https://github.com/user-attachments/assets/f4862b62-7066-48a7-aac1-8fc1e3198259" />

<img width="1920" height="1080" alt="ida_3V31SXNy3w" src="https://github.com/user-attachments/assets/4ed8da4e-bd90-4427-acea-a65e8390fad2" />

Thứ tự này là:

  - C = F(G(G(G(G(F(P)))))) = F(G^4(F(P)))

Hàm F (RC4 với key là 12345678) còn G là DES (ECB, key 30988C6642A8D86E)

Với:

 - P: password nhập vào
 
 - C: hằng đích 24 28 14 4A 11 A0 7F E4
 
 - Suy ngược từ ngoài vào trong ta thu được password cần là debugger

Thử vào ta có: 

<img width="979" height="512" alt="image" src="https://github.com/user-attachments/assets/355fba15-a5be-4d56-967f-bd6a8f125b80" />


