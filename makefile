all: encrypt decrypt
encrypt:
	gcc encrypt.c -o encrypt -lcrypto
decrypt:
	gcc decrypt.c -o decrypt -lcrypto