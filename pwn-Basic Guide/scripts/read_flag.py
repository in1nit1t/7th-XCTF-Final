from pwn import *

sh = remote("127.0.0.1", 10000)

def choice(idx):
    sh.recv()
    sh.sendline(str(idx).encode())

def win():
    sh.recv()
    sh.sendline(b"123")
    for _ in range(4):
        choice(3)
    for _ in range(5):
        choice(2)

sh.sendlineafter(b"room.\n", b'3')
win()
sh.recvuntil(b"win!\n")
enc_flag = sh.recvuntil(b"rebuilding...", drop=True)
with open("flag", "wb") as f:
    f.write(enc_flag)
