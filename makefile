all:
	gcc init.c -o init -lcrypto
	gcc brute_force.c -o bf -lcrypto

