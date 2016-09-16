/*testAESkey.c
Copyright (C) 2013 Michel Dubois

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.*/

/* Using openSSL in command Line:
python -c "print(bytearray.fromhex('6bc1bee22e409f96e93d7e117393172a').decode())" > plaintext.bin
echo -n 'Attack at dawn!!' | openssl enc -v -aes-128-ecb -K 01000000000000000000000000000000 -nosalt -nopad -out result.bin
cat cat result.bin | hexdump -C
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/aes.h>

#define couleur(param) printf("\033[%sm",param)

static unsigned long iterations;
static int clearLengthInByte=0, keyLengthInByte=0, cipherLengthInByte=0;




void info(void) {
	couleur("31");
	printf("Michel Dubois -- AES test key -- (c) 2016\n");
	couleur("0");
}


void clearScreen(void) {
	printf("\x1b[2J\x1b[1;1H");
}


void initBlock(unsigned char block[], int nbrOfBytes, char *value) {
	int i=0, j=0;
	unsigned char temp[nbrOfBytes*2];
	char c;

	block[0] = 0xff;
	for (i=0; i<nbrOfBytes*2; i++) {
		c = value[i];
		if (c>=97) { temp[i] = c - 87; }
		else if (c>=65) { temp[i] = c - 55; }
		else { temp[i] = c - 48; }
	}
	j=0;
	for (i=0; i<nbrOfBytes*2; i+=2) {
		block[j] = temp[i]*16 + temp[i+1];
		j++;
	}
}


char* printBlock(unsigned char block[], int nbrOfBytes) {
	char *result = calloc((nbrOfBytes*2)+1, sizeof(char));
	result[nbrOfBytes*2] = '\0';
	int i=0, j=0;
	for (i=0; i<nbrOfBytes; i++) {
		sprintf(&result[j], "%x", (block[i] & 0xf0)>>4);
		sprintf(&result[j+1], "%x", (block[i] & 0x0f));
		j+=2;
	}
	return(result);
}


void intToHex(unsigned long val, int nbrOfBytes, unsigned char block[]) {
	int i=0;
	for (i=nbrOfBytes-1; i>=0; i--) {
		block[i] = val % 256;
		val /= 256;
	}
}


void intToSpecialHex(unsigned long val, int nbrOfBytes, unsigned char block[]) {
	int i=0, limit=4;
	nbrOfBytes = nbrOfBytes-1;
	for (i=nbrOfBytes; i>=limit; i--) {
		block[i] = 0;
	}
	for (i=nbrOfBytes-limit; i>=0; i--) {
		block[i] = val % 256;
		val /= 256;
	}
}


void hexDump(FILE *fd, char *title, unsigned char *s, int length) {
	int i=0;
	for(i=0; i<length; ++i) {
		if(i%16 == 0) { fprintf(fd, "\n%s  %04x", title, i); }
		fprintf(fd, " %02x", s[i]);
	}
	fprintf(fd, "\n\n");
}


void displayResults(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	printf("Clear: %s,\tKey: %s,\tCipher: %s\n",
		printBlock(clear, clearLengthInByte),
		printBlock(key, keyLengthInByte),
		printBlock(cipher, cipherLengthInByte));
}


void AESencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	AES_ecb_encrypt(clear, cipher, &expandKey, AES_ENCRYPT);
}


void AESdecrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_decrypt_key(key, keyLengthInByte*8, &expandKey);
	AES_ecb_encrypt(clear, cipher, &expandKey, AES_DECRYPT);
}


void AESdisplayExpansionCipherKey(unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	hexDump(stdout, "AES_KEY", (unsigned char *)&expandKey, keyLengthInByte*11);
}


void testAEScipher(void) {
	clock_t tic, tac;
	double executionTime = 0.0;
	unsigned long i=0;
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];

	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	tic = clock();
	for (i=0; i<iterations; i++) {
		intToHex(i, clearLengthInByte, clear);
		AESencrypt(clear, cipher, key);
		printf("%lu\t", i);
		displayResults(clear, cipher, key);
	}
	tac = clock();
	executionTime = (double)(tac - tic) / CLOCKS_PER_SEC;
	printf("Execution time: %.8f\n", executionTime);
}


void testKey(void) {
	unsigned long i=0;
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		intToHex(0, clearLengthInByte, clear);
		for (i=0; i<iterations; i++) {
			intToSpecialHex(i, keyLengthInByte, key);
			AESencrypt(clear, cipher, key);
			fprintf(fic, "%s\n", printBlock(cipher, cipherLengthInByte));
			if (i%10000 == 0) {
				printf("%lu\t", i);
				displayResults(clear, cipher, key);
			}
		}
		printf("%lu\t", i);
		displayResults(clear, cipher, key);
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
}


void vectorTest(void) {
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];

	initBlock(clear, clearLengthInByte, "3243f6a8885a308d313198a2e0370734");
	initBlock(key, keyLengthInByte, "2b7e151628aed2a6abf7158809cf4f3c");
	AESdisplayExpansionCipherKey(key);
	AESencrypt(clear, cipher, key);
	displayResults(clear, cipher, key);
	printf("Normal result: 3925841d02dc09fbdc118597196a0b32\n");
	AESdecrypt(clear, cipher, key);
	displayResults(clear, cipher, key);

	initBlock(clear, clearLengthInByte, "00112233445566778899aabbccddeeff");
	initBlock(key, keyLengthInByte, "000102030405060708090a0b0c0d0e0f");
	AESdisplayExpansionCipherKey(key);
	AESencrypt(clear, cipher, key);
	displayResults(clear, cipher, key);
	printf("Normal result: 69c4e0d86a7b0430d8cdb78070b4c55a\n");
	AESdecrypt(clear, cipher, key);
	displayResults(clear, cipher, key);
}


void testGreatNumber(void) {
	unsigned long i=0;
	double power=50.0;
	double test = pow(2, power);

	for (i=0; i<iterations; i++) {
		printf("%lu + 2^%0.0f =\t%0.0f\n", i, power, test);
		test += 1.0f;
	}
}


int main(void) {
	clearScreen();
	info();
	iterations = 4000000;
	clearLengthInByte = 16;
	keyLengthInByte = 16;
	cipherLengthInByte = 16;

	vectorTest();
	testKey();
	//testAEScipher();
	//testGreatNumber();
	return(EXIT_SUCCESS);
}
