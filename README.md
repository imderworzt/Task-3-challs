## Antidebug challs

### anti1.exe

Bài này về mặt debug, chỉ cần đặt bp ở dòng call IsDebbugPresent là debug được

Hơn nữa, cách viết mã của bài này khá lộ, không cần debug cũng giải ra được

Cơ chế hoạt động:
  - Key là BKSEECCCC!!!
  - Nhìn vào graph view trong ida, bạn sẽ thấy một chuỗi byte:

```
loc_401AD5:
mov     [ebp+var_B8], 0
mov     [ebp+var_B7], 0
mov     [ebp+var_B6], 0
mov     [ebp+var_B5], 0
mov     [ebp+var_B4], 6
mov     [ebp+var_B3], 38h ; '8'
mov     [ebp+var_B2], 26h ; '&'
mov     [ebp+var_B1], 77h ; 'w'
mov     [ebp+var_B0], 30h ; '0'
mov     [ebp+var_AF], 58h ; 'X'
mov     [ebp+var_AE], 7Eh ; '~'
mov     [ebp+var_AD], 42h ; 'B'
mov     [ebp+var_AC], 2Ah ; '*'
mov     [ebp+var_AB], 7Fh
mov     [ebp+var_AA], 3Fh ; '?'
mov     [ebp+var_A9], 29h ; ')'
mov     [ebp+var_A8], 1Ah
mov     [ebp+var_A7], 21h ; '!'
mov     [ebp+var_A6], 36h ; '6'
mov     [ebp+var_A5], 37h ; '7'
mov     [ebp+var_A4], 1Ch
mov     [ebp+var_A3], 55h ; 'U'
mov     [ebp+var_A2], 49h ; 'I'
mov     [ebp+var_A1], 12h
mov     [ebp+var_A0], 30h ; '0'
mov     [ebp+var_9F], 78h ; 'x'
mov     [ebp+var_9E], 0Ch
mov     [ebp+var_9D], 28h ; '('
mov     [ebp+var_9C], 30h ; '0'
mov     [ebp+var_9B], 30h ; '0'
mov     [ebp+var_9A], 37h ; '7'
mov     [ebp+var_99], 1Ch
mov     [ebp+var_98], 21h ; '!'
mov     [ebp+var_97], 12h
mov     [ebp+var_96], 7Eh ; '~'
mov     [ebp+var_95], 52h ; 'R'
mov     [ebp+var_94], 2Dh ; '-'
mov     [ebp+var_93], 26h ; '&'
mov     [ebp+var_92], 60h ; '`'
mov     [ebp+var_91], 1Ah
mov     [ebp+var_90], 24h ; '$'
mov     [ebp+var_8F], 2Dh ; '-'
mov     [ebp+var_8E], 37h ; '7'
mov     [ebp+var_8D], 72h ; 'r'
mov     [ebp+var_8C], 1Ch
mov     [ebp+var_8B], 45h ; 'E'
mov     [ebp+var_8A], 44h ; 'D'
mov     [ebp+var_89], 43h ; 'C'
mov     [ebp+var_88], 37h ; '7'
mov     [ebp+var_87], 2Ch ; ','
mov     [ebp+var_86], 6Ch ; 'l'
mov     [ebp+var_85], 7Ah ; 'z'
mov     [ebp+var_84], 38h ; '8'
mov     [ebp+var_7C], 0
```

  - Và những gì chương trình này làm là 
