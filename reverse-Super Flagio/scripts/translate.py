buf = list(map(ord, "?" * 32))

buf[0] = (buf[0] ^ 30) - 1

for i in range(1, 32):
	buf[i] ^= buf[i - 1]
	if i % 2 == 0 or i == 31:
		buf[i] -= 1
	else:
		buf[i] += 1
	buf[i] &= 0xFF

print(buf)