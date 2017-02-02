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
cat result.bin | hexdump -C

Searching collisions
sort -u result_0.dat > uniquely_sorted.dat
wc -l uniquely_sorted.dat result_0.dat
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "openssl_array.h"


#define couleur(param) printf("\033[%sm",param)


static short randProcess=0;
static unsigned long iterations;
static int clearLengthInByte=0, keyLengthInByte=0, cipherLengthInByte=0;
static int verbose=0, power=0, roundNbr=0, decal=0, schema=0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- AES test key -- (c) 2016\n");
	couleur("0");
	printf("Syntaxe:\n");
	printf("\tWith 1 argument (speed tests): testAESkey <power>\n");
	printf("\t\t<power> -> 2^power keys generated\n");
	printf("\tWith 2 argument (full encryption tests): testAESkey <power> <type>\n");
	printf("\t\t<power> -> 2^power keys generated\n");
	printf("\t\t<type> -> key processing type 'rand', 'incr'\n");
	printf("\tWith 3 argument (display expansion key): testAESkey <power> <decal> <schema>\n");
	printf("\t\t<power> -> 2^power keys generated\n");
	printf("\t\t<decal> -> value for decalage of bytes\n");
	printf("\t\t<schema> -> schema of key padding 0 >= s >= 255\n");
	printf("\tWith 4 argument (partial encryption tests): testAESkey <power> <decal> <round> <schema>\n");
	printf("\t\t<power> -> 2^power keys generated\n");
	printf("\t\t<decal> -> value for decalage of bytes\n");
	printf("\t\t<round> -> number of rounds 0 >= r >= 10\n");
	printf("\t\t<schema> -> schema of key padding 0 >= s >= 255\n");
}


void clearScreen(void) {
	printf("\x1b[2J\x1b[1;1H");
}


unsigned int charBlock2intBlock(const unsigned char *val) {
	return(
		((unsigned int)(val)[0] << 24)
		^ ((unsigned int)(val)[1] << 16)
		^ ((unsigned int)(val)[2] << 8)
		^ ((unsigned int)(val)[3])
	);
}


void intBlock2charBlock(unsigned char *out, unsigned int in) {
	(out)[0] = (unsigned char)((in) >> 24);
	(out)[1] = (unsigned char)((in) >> 16);
	(out)[2] = (unsigned char)((in) >>  8);
	(out)[3] = (unsigned char)(in);
}


unsigned int swap32bitsBlock(unsigned int val) {
	return(
		((val>>24)&0xff) | // move byte 3 to byte 0
		((val<<8)&0xff0000) | // move byte 1 to byte 2
		((val>>8)&0xff00) | // move byte 2 to byte 1
		((val<<24)&0xff000000)
	);
}


double mean(int m, double data[]) {
	int i = 0;
	double result = 0.0;
	for (i=0; i<m; i++) {
		result += data[i];
	}
	return(result / (double)m);
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


char* printBlock(unsigned char block[], int nbrOfBytes, char result[]) {
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


void intToSpecialHex(int limit, unsigned long val, int nbrOfBytes, unsigned char block[]) {
	// limit is the decal value in byte
	int i=0;
	nbrOfBytes = nbrOfBytes-1;
	for (i=nbrOfBytes; i>=limit; i--) {
		block[i] = schema;
	}
	for (i=limit-1; i>=0; i--) {
		block[i] = val % 256;
		val /= 256;
	}
}


void randToSpecialHex(int limit, int nbrOfBytes, unsigned char block[]) {
	// limit is the decal value in byte
	int i=0, cpt=0;
	unsigned char randBytes[nbrOfBytes-limit];

	RAND_bytes(randBytes, sizeof(randBytes));
	nbrOfBytes = nbrOfBytes-1;
	for (i=nbrOfBytes; i>=limit; i--) {
		block[i] = 0;
	}
	cpt=0;
	for (i=limit-1; i>=0; i--) {
		block[i] = randBytes[cpt];
		cpt++;
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


void compactHexDump(unsigned char *s, char result[]) {
	int byte = 0, r = 0, shift=0;

	for (r=0; r<11; r++) {
		for (byte=0; byte<16; byte++) {
			shift = (r * keyLengthInByte) + byte;
			if (shift == 0) {
				sprintf(result, "%02x", s[shift]);
			} else {
				sprintf(result, "%s%02x", result, s[shift]);
			}
		}
		sprintf(result, "%s ", result);
	}
	sprintf(result, "%s\n", result);
}


void displayResults(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	char resultClear[(clearLengthInByte*2)+1];
	char resultKey[(keyLengthInByte*2)+1];
	char resultCipher[(cipherLengthInByte*2)+1];
	printf("Clear: %s,\tKey: %s,\tCipher: %s\n",
		printBlock(clear, clearLengthInByte, resultClear),
		printBlock(key, keyLengthInByte, resultKey),
		printBlock(cipher, cipherLengthInByte, resultCipher));
}


void AESencryptByRound(unsigned char clear[], unsigned char cipher[], unsigned char key[], int round) {
	int r=0;
	AES_KEY expandKey;
	const unsigned int *rk;
	unsigned int s0=0, s1=0, s2=0, s3=0, t0=0, t1=0, t2=0, t3=0;

	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	rk = expandKey.rd_key;

	for (r=0; r<=round; r++) {
		if (r==0) {
			s0 = charBlock2intBlock(clear) ^ swap32bitsBlock(rk[0]);
			s1 = charBlock2intBlock(clear+4) ^ swap32bitsBlock(rk[1]);
			s2 = charBlock2intBlock(clear+8) ^ swap32bitsBlock(rk[2]);
			s3 = charBlock2intBlock(clear+12) ^ swap32bitsBlock(rk[3]);
		} else {
			if (r % 2 == 0) {
				if (r == 10) {
					s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ swap32bitsBlock(rk[(4*r)]);
					s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ swap32bitsBlock(rk[(4*r)+1]);
					s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ swap32bitsBlock(rk[(4*r)+2]);
					s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ swap32bitsBlock(rk[(4*r)+3]);
				} else {
					s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ swap32bitsBlock(rk[(4*r)]);
					s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ swap32bitsBlock(rk[(4*r)+1]);
					s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ swap32bitsBlock(rk[(4*r)+2]);
					s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ swap32bitsBlock(rk[(4*r)+3]);
				}
			} else {
				t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ swap32bitsBlock(rk[(4*r)]);
				t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ swap32bitsBlock(rk[(4*r)+1]);
				t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ swap32bitsBlock(rk[(4*r)+2]);
				t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ swap32bitsBlock(rk[(4*r)+3]);
			}
		}
	}

	if (round % 2 == 0) {
		intBlock2charBlock(cipher, s0);
		intBlock2charBlock(cipher+4, s1);
		intBlock2charBlock(cipher+8, s2);
		intBlock2charBlock(cipher+12, s3);
	} else {
		intBlock2charBlock(cipher, t0);
		intBlock2charBlock(cipher+4, t1);
		intBlock2charBlock(cipher+8, t2);
		intBlock2charBlock(cipher+12, t3);
	}
}


void AESencrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	AES_encrypt(clear, cipher, &expandKey);
}


void AESdecrypt(unsigned char clear[], unsigned char cipher[], unsigned char key[]) {
	AES_KEY expandKey;
	AES_set_decrypt_key(key, keyLengthInByte*8, &expandKey);
	AES_decrypt(clear, cipher, &expandKey);
}


void AESdisplayExpansionCipherKey(unsigned char key[]) {
	AES_KEY expandKey;
	char result[keyLengthInByte*23];
	AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
	hexDump(stdout, "AES_KEY", (unsigned char *)&expandKey, keyLengthInByte*11);
	compactHexDump((unsigned char *)&expandKey, result);
	printf("%s", result);
}


void testAEScipher(short full, int nbrRound) {
	int maxTest=8, curTest=0;
	clock_t tic[maxTest], tac[maxTest];
	double execTime[maxTest], m=0;
	unsigned long i=0;
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];
	FILE *fic = fopen("time.dat", "a");

	initBlock(key, keyLengthInByte, "80000000000000000000000000000000");
	intToHex(0, clearLengthInByte, clear);
	for (curTest=0; curTest<maxTest; curTest++) {
		tic[curTest] = clock();
		for (i=0; i<iterations; i++) {
			if (full) {
				AESencrypt(clear, cipher, key);
			} else {
				AESencryptByRound(clear, cipher, key, nbrRound);
			}
		}
		tac[curTest] = clock();
	}
	printf("2^%d=%lu iterations.\n", power, iterations);
	for (curTest=0; curTest<maxTest; curTest++) {
		execTime[curTest] = (double)(tac[curTest] - tic[curTest]) / CLOCKS_PER_SEC;
		printf("%.8f ", execTime[curTest]);
	}
	m = mean(maxTest, execTime);
	printf(" (mean: %.8f)\n", m);
	fprintf(fic, "%lu %.8f\n", iterations, m);
	fclose(fic);
}


void fullKeyExpansionTest(void) {
	clock_t tic, tac;
	double executionTime = 0.0;
	int step=0;
	unsigned long i=0;
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];
	char resultCipher[(cipherLengthInByte*2)+1];

	couleur("31");
	printf("\nAES tests: 2^%d=%lu iterations\n", power, iterations);
	couleur("0");

	RAND_seed("/dev/urandom", 2048);
	if (RAND_status()) {
		FILE *fic = fopen("result.dat", "w");
		if (fic != NULL) {
			if (power <= 8) { step=1; } else { step=100000; }
			intToHex(0, clearLengthInByte, clear);
			tic = clock();
			for (i=0; i<iterations; i++) {
				if (randProcess) {
					randToSpecialHex(decal, keyLengthInByte, key);
				} else {
					intToSpecialHex(decal, i, keyLengthInByte, key);
				}
				AESencrypt(clear, cipher, key);
				fprintf(fic, "%s\n", printBlock(cipher, cipherLengthInByte, resultCipher));
				if (step == 1) {
					printf("%lu\t", i);
					displayResults(clear, cipher, key);
				}
			}
			tac = clock();
			if ((verbose) && (step > 1)) {
				printf("%lu\t", i-1);
				displayResults(clear, cipher, key);
			}
			fclose(fic);
			executionTime = (double)(tac - tic) / CLOCKS_PER_SEC;
			printf("Execution time: %.8f\n", executionTime);
		} else {
			printf("INFO: open error\n");
			exit(EXIT_FAILURE);
		}
	} else {
		printf("INFO: random error\n");
		exit(EXIT_FAILURE);
	}
}


void partialKeyExpansionTest(void) {
	clock_t tic, tac;
	double executionTime = 0.0;
	int step=0;
	unsigned long i=0;
	char nameResult[20];
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];
	char resultCipher[(cipherLengthInByte*2)+1];

	couleur("31");
	printf("\nAES tests: 2^%d=%lu iterations, number of rounds %d\n", power, iterations, roundNbr);
	couleur("0");

	sprintf(nameResult, "result_%d.dat", schema);
	FILE *fic = fopen(nameResult, "w");
	if (fic != NULL) {
		if (power <= 8) { step=1; } else { step=100000; }
		intToHex(0, clearLengthInByte, clear);
		tic = clock();
		for (i=0; i<iterations; i++) {
			intToSpecialHex(decal, i, keyLengthInByte, key);
			AESencryptByRound(clear, cipher, key, roundNbr);
			fprintf(fic, "%s\n", printBlock(cipher, cipherLengthInByte, resultCipher));
			if (step == 1) {
				printf("%lu\t", i);
				displayResults(clear, cipher, key);
			}
		}
		tac = clock();
		if ((verbose) && (step > 1)) {
			printf("%lu\t", i-1);
			displayResults(clear, cipher, key);
		}
		fclose(fic);
		executionTime = (double)(tac - tic) / CLOCKS_PER_SEC;
		printf("Execution time: %.8f\n", executionTime);
	} else {
		printf("INFO: file creation error\n");
		exit(EXIT_FAILURE);
	}
}


void displayKeyExpansion(void) {
	clock_t tic, tac;
	double executionTime = 0.0;
	int step=0;
	unsigned long i=0;
	char nameResult[20];
	char result[keyLengthInByte*23];
	AES_KEY expandKey;
	unsigned char key[keyLengthInByte];

	couleur("31");
	printf("\nAES tests: 2^%d=%lu iterations\n", power, iterations);
	couleur("0");

	sprintf(nameResult, "key_%d.dat", schema);
	FILE *fic = fopen(nameResult, "w");
	if (fic != NULL) {
		if (power <= 8) { step=1; } else { step=100000; }
		tic = clock();
		for (i=0; i<iterations; i++) {
			intToSpecialHex(decal, i, keyLengthInByte, key);
			AES_set_encrypt_key(key, keyLengthInByte*8, &expandKey);
			compactHexDump((unsigned char *)&expandKey, result);
			fprintf(fic, "%s", result);
			if (step == 1) {
				printf("%lu %s", i, result);
			}
		}
		tac = clock();
		if ((verbose) && (step > 1)) {
			printf("%lu\t", i-1);
		}
		fclose(fic);
		executionTime = (double)(tac - tic) / CLOCKS_PER_SEC;
		printf("Execution time: %.8f\n", executionTime);
	} else {
		printf("INFO: file creation error\n");
		exit(EXIT_FAILURE);
	}
}


void vectorTest(void) {
	unsigned char clear[clearLengthInByte];
	unsigned char key[keyLengthInByte];
	unsigned char cipher[cipherLengthInByte];

	couleur("31");
	printf("\nAES test with NIST vectors\n");
	couleur("0");

	initBlock(clear, clearLengthInByte, "3243f6a8885a308d313198a2e0370734");
	initBlock(key, keyLengthInByte, "2b7e151628aed2a6abf7158809cf4f3c");
	AESencrypt(clear, cipher, key);
	displayResults(clear, cipher, key);
	AESencryptByRound(clear, cipher, key, 10);
	displayResults(clear, cipher, key);
	printf("Normal result: 3925841d02dc09fbdc118597196a0b32\n");
	AESdisplayExpansionCipherKey(key);

}


int main(int argc, char *argv[]) {
	clearLengthInByte = 16;
	keyLengthInByte = 16;
	cipherLengthInByte = 16;

	switch (argc) {
		case 2:
			power = atoi(argv[1]);
			iterations = (unsigned long)pow(2, power);
			clearScreen();
			testAEScipher(1, 0);
			return(EXIT_SUCCESS);
			break;
		case 3:
			power = atoi(argv[1]);
			decal = 16;
			iterations = (unsigned long)pow(2, power);
			if (!strncmp(argv[2], "rand", 4)) { randProcess = 1; }
			clearScreen();
			fullKeyExpansionTest();
			return(EXIT_SUCCESS);
			break;
		case 4:
			power = atoi(argv[1]);
			decal = atoi(argv[2]);
			schema = atoi(argv[3]);
			iterations = (unsigned long)pow(2, power);
			clearScreen();
			displayKeyExpansion();
			return(EXIT_SUCCESS);
			break;
		case 5:
			power = atoi(argv[1]);
			decal = atoi(argv[2]);
			roundNbr = atoi(argv[3]);
			schema = atoi(argv[4]);
			iterations = (unsigned long)pow(2, power);
			clearScreen();
			partialKeyExpansionTest();
			return(EXIT_SUCCESS);
			break;
		default:
			clearScreen();
			usage();
			vectorTest();
			exit(EXIT_FAILURE);
			break;
	}
}


/*
TODO
For one key print all 10 round keys


https://fr.mathworks.com/matlabcentral/answers/197246-finding-duplicate-strings-in-a-cell-array-and-their-index
GNU octave analyse

listing of find_duplicate.m

#! /opt/local/bin/octave-cli -qf

clear all;

printf('Data analysis\n');

tic;
load analyse.dat;
[D,~,X] = unique(data);
[n, bin] = histc(X,unique(X));
multiple = find(n > 1);
index = find(ismember(bin, multiple));
toc;

printf('Result is:\n');
index



*/
