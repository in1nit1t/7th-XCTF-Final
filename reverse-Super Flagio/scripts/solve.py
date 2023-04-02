cipher = [ 94, 106, 91, 110, 86, 100, 82, 20, 32, 20, 80, 21, 83, 107, 88, 98, 81, 19, 79, 10, 49, 117, 68, 120, 61, 13, 75, 115, 48, 8, 76, 123 ]

for i in range(31, 0, -1):
	if i % 2 == 0 or i == 31:
		cipher[i] += 1
	else:
		cipher[i] -= 1
	cipher[i] &= 0xFF
	cipher[i] ^= cipher[i - 1]

cipher[0] = (cipher[0] + 1) ^ 30

flag = ''.join(map(chr, cipher))
print(flag)