/*cipher
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/sha.h>

#define couleur(param) printf("\033[%sm",param)


static unsigned long iterations;
static int clearLengthInByte=0, keyLengthInByte=0, cipherLengthInByte=0;
static int algo = 0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- cipher -- (c) 2014\n\n");
	couleur("0");
	printf("Syntaxe: cipher <num> <algo>\n");
	printf("\t<num> -> sample size\n");
	printf("\t<algo> -> 'aes', 'blowfish', 'camellia', 'des', 'rc4', 'cast', 'idea', 'md4', 'md5', 'sha1' or 'sha256'\n");
}


void clearScreen(void) {
	printf("\x1b[2J\x1b[1;1H");
}


void displayInfos(char text[], short key) {
	couleur("32");
	if (key) {
		printf("INFO: %s\tclear length: %d,\tkey length: %d,\tcipher length: %d\n", text, clearLengthInByte, keyLengthInByte, cipherLengthInByte);
	} else {
		printf("INFO: %s\ttext length: %d,\tdigest length: %d\n", text, clearLengthInByte, cipherLengthInByte);
	}
	couleur("0");
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
		sprintf(&result[j], "%X", (block[i] & 0xf0)>>4);
		sprintf(&result[j+1], "%X", (block[i] & 0x0f));
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


void displayResults(unsigned char clear[], unsigned char cipher[], unsigned char key[], short k) {
	if (k) {
		printf("Clear: %s,\tKey: %s,\tCipher: %s\n",
			printBlock(clear, clearLengthInByte),
			printBlock(key, keyLengthInByte),
			printBlock(cipher, cipherLengthInByte));
	} else {
		printf("Text: %s,\tDigest: %s\n",
			printBlock(clear, clearLengthInByte),
			printBlock(cipher, cipherLengthInByte));
	}
}


void AESencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	AES_ecb_encrypt(clear, cipher, &expandKey, AES_ENCRYPT);
}


void BlowfishEncrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	BF_KEY expandKey;
	BF_set_key(&expandKey, keyLengthInByte, key);
	BF_ecb_encrypt(clear, cipher, &expandKey, BF_ENCRYPT);
}


void DESencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	DES_cblock clearDES;
	DES_cblock cipherDES;
	DES_cblock keyDES;
	DES_key_schedule expandKey;

	memcpy(clearDES, clear, clearLengthInByte);
	memcpy(keyDES, key, keyLengthInByte);
	DES_set_key(&keyDES, &expandKey);
	DES_ecb_encrypt(&clearDES, &cipherDES, &expandKey, DES_ENCRYPT);
	memcpy(cipher, cipherDES, cipherLengthInByte);
}


void camelliaEncrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	CAMELLIA_KEY expandKey;
	Camellia_set_key(key, keyLengthInByte*8, &expandKey);
	Camellia_ecb_encrypt(clear, cipher, &expandKey, CAMELLIA_ENCRYPT);
}


void RC4encrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	RC4_KEY rc4_key;
	RC4_set_key(&rc4_key, keyLengthInByte, key);
	RC4(&rc4_key, cipherLengthInByte, clear, cipher);
}


void CASTencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	CAST_KEY expandKey;
	CAST_set_key(&expandKey, keyLengthInByte*8, key);
	CAST_ecb_encrypt(clear, cipher, &expandKey, CAST_ENCRYPT);
}


void IDEAencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	IDEA_KEY_SCHEDULE expandKey;
	idea_set_encrypt_key(key, &expandKey);
	idea_ecb_encrypt(clear, cipher, &expandKey);
}


void MD4Hash(unsigned char clear[], unsigned char cipher[]) {
	MD4(clear, clearLengthInByte, cipher);
}


void MD5Hash(unsigned char clear[], unsigned char cipher[]) {
	MD5(clear, clearLengthInByte, cipher);
}


void SHA1Hash(unsigned char clear[], unsigned char cipher[]) {
	SHA1(clear, clearLengthInByte, cipher);
}


void SHA256Hash(unsigned char clear[], unsigned char cipher[]) {
	SHA256(clear, clearLengthInByte, cipher);
}


void generateFile(void) {
	unsigned long i=0;
	short k=0;
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
		for (i=0; i<iterations; i++) {
			intToHex(i, clearLengthInByte, clear);
			if (algo == 1 /*AES 128*/) { AESencrypt(clear, cipher, key); k=1; }
			if (algo == 2 /*Blowfish*/) { BlowfishEncrypt(clear, cipher, key); k=1; }
			if (algo == 3 /*DES*/) { DESencrypt(clear, cipher, key); k=1; }
			if (algo == 4 /*Camellia*/) { camelliaEncrypt(clear, cipher, key); k=1; }
			if (algo == 5 /*RC4*/) { RC4encrypt(clear, cipher, key); k=1; }
			if (algo == 6 /*CAST*/) { CASTencrypt(clear, cipher, key); k=1; }
			if (algo == 7 /*MD4*/) { MD4Hash(clear, cipher); k=0; }
			if (algo == 8 /*MD5*/) { MD5Hash(clear, cipher); k=0; }
			if (algo == 9 /*SHA1*/) { SHA1Hash(clear, cipher); k=0; }
			if (algo == 10 /*SHA256*/) { SHA256Hash(clear, cipher); k=0; }
			if (algo == 11 /*idea*/) { IDEAencrypt(clear, cipher, key); k=1; }
			fprintf(fic, "%s\n", printBlock(cipher, cipherLengthInByte));
			if (i%1000 == 0) {
				printf("%lu\t", i);
				displayResults(clear, cipher, key, k);
			}
		}
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
}


void vectorTest(void) {
	unsigned char *clear = NULL;
	unsigned char *key = NULL;
	unsigned char *cipher = NULL;

	couleur("31"); printf("\nVector test\n"); couleur("0");

	// AES
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/rijndael/rijndael.html
	clearLengthInByte = 16;
	keyLengthInByte = 16;
	cipherLengthInByte = 16;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("AES", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	AESencrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: 0EDD33D3C621E546455BD8BA1418BEC8\n\n");
	free(clear); free(key); free(cipher);

	// Blowfish
	// https://www.schneier.com/code/vectors.txt
	clearLengthInByte = 8;
	keyLengthInByte = 8;
	cipherLengthInByte = 8;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("Blowfish", 1);
	initBlock(key, keyLengthInByte, "00000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	BlowfishEncrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: 4EF997456198DD78\n\n");
	free(clear); free(key); free(cipher);

	// DES
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/index.html
	clearLengthInByte = 8;
	keyLengthInByte = 8;
	cipherLengthInByte = 8;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("DES", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	DESencrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: 95A8D72813DAA94D\n\n");
	free(clear); free(key); free(cipher);

	// Camellia
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/camellia/camellia.html
	clearLengthInByte = 16;
	keyLengthInByte = 16;
	cipherLengthInByte = 16;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("Camellia", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	camelliaEncrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: 6C227F749319A3AA7DA235A9BBA05A2C\n\n");
	free(clear); free(key); free(cipher);

	// RC4
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/sc/arcfour/Rc4-arcfour-128.verified.test-vectors
	clearLengthInByte = 16;
	keyLengthInByte = 16;
	cipherLengthInByte = 16;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("RC4", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	RC4encrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: 4ABC7C316D52E3FF0DF7370539EB7BD3\n\n");
	free(clear); free(key); free(cipher);

	// CAST
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/cast-128/Cast-128-128-64.verified.test-vectors
	clearLengthInByte = 8;
	keyLengthInByte = 16;
	cipherLengthInByte = 8;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("CAST", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	CASTencrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: EF854DE5D7D1895B\n\n");
	free(clear); free(key); free(cipher);

	// idea
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors
	clearLengthInByte = 8;
	keyLengthInByte = 16;
	cipherLengthInByte = 8;
	clear = (unsigned char *)calloc(clearLengthInByte, sizeof(clear));
	key = (unsigned char *)calloc(keyLengthInByte, sizeof(key));
	cipher = (unsigned char *)calloc(cipherLengthInByte, sizeof(cipher));
	displayInfos("IDEA", 1);
	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	IDEAencrypt(clear, cipher, key);
	displayResults(clear, cipher, key, 1);
	printf("Should be: B1F5F7F87901370F\n\n");
	free(clear); free(key); free(cipher);
}


int main(int argc, char *argv[]) {
	clearScreen();
	switch (argc) {
		case 3:
			if (strncmp(argv[2], "aes", 3) == 0) { algo = 1; }
			else if (strncmp(argv[2], "blowfish", 8) == 0) { algo = 2; }
			else if (strncmp(argv[2], "des", 3) == 0) { algo = 3; }
			else if (strncmp(argv[2], "camellia", 4) == 0) { algo = 4; }
			else if (strncmp(argv[2], "rc4", 3) == 0) { algo = 5; }
			else if (strncmp(argv[2], "cast", 6) == 0) { algo = 6; }
			else if (strncmp(argv[2], "md4", 3) == 0) { algo = 7; }
			else if (strncmp(argv[2], "md5", 3) == 0) { algo = 8; }
			else if (strncmp(argv[2], "sha1", 4) == 0) { algo = 9; }
			else if (strncmp(argv[2], "sha256", 6) == 0) { algo = 10; }
			else if (strncmp(argv[2], "idea", 4) == 0) { algo = 11; }
			else {
				usage();
				vectorTest();
				exit(EXIT_FAILURE);
			}
			break;
		default:
			usage();
			vectorTest();
			exit(EXIT_FAILURE);
			break;
	}
	iterations = atol(argv[1]);
	switch (algo) {
		case 1: // AES
			clearLengthInByte = 16;
			keyLengthInByte = 16;
			cipherLengthInByte = 16;
			displayInfos("AES", 1);
			break;
		case 2: // Blowfish
			clearLengthInByte = 8;
			keyLengthInByte = 8;
			cipherLengthInByte = 8;
			displayInfos("Blowfish", 1);
			break;
		case 3: // DES
			clearLengthInByte = 8;
			keyLengthInByte = 8;
			cipherLengthInByte = 8;
			displayInfos("DES", 1);
			break;
		case 4: // Camellia
			clearLengthInByte = 16;
			keyLengthInByte = 16;
			cipherLengthInByte = 16;
			displayInfos("Camellia", 1);
			break;
		case 5: // RC4
			clearLengthInByte = 16;
			keyLengthInByte = 16;
			cipherLengthInByte = 16;
			displayInfos("RC4", 1);
			break;
		case 6: // CAST
			clearLengthInByte = 8;
			keyLengthInByte = 16;
			cipherLengthInByte = 8;
			displayInfos("CAST", 1);
			break;
		case 7: // MD4
			clearLengthInByte = 16;
			cipherLengthInByte = MD4_DIGEST_LENGTH;
			displayInfos("MD4", 0);
			break;
		case 8: // MD5
			clearLengthInByte = 16;
			cipherLengthInByte = MD5_DIGEST_LENGTH;
			displayInfos("MD5", 0);
			break;
		case 9: // SHA1
			clearLengthInByte = 16;
			cipherLengthInByte = SHA_DIGEST_LENGTH;
			displayInfos("SHA1", 0);
			break;
		case 10: // SHA256
			clearLengthInByte = 16;
			cipherLengthInByte = SHA256_DIGEST_LENGTH;
			displayInfos("SHA256", 0);
			break;
		case 11: // idea
			clearLengthInByte = 8;
			keyLengthInByte = 16;
			cipherLengthInByte = 8;
			displayInfos("IDEA", 1);
			break;
		default:
			break;
	}
	generateFile();
	exit(EXIT_SUCCESS);
}
