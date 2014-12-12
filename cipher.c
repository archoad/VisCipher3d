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
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <openssl/rc4.h>


#define couleur(param) printf("\033[%sm",param)


static unsigned long iterations;


static int algo = 0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- cipher -- (c) 2014\n\n");
	couleur("0");
	printf("Syntaxe: cipher <num> <algo>\n");
	printf("\t<num> -> sample size\n");
	printf("\t<algo> -> 'aes', 'blowfish', '3des', 'des' or 'rc4'\n");
}


unsigned char *putToNbytesBlock(unsigned char *block, int size, int n) {
	int i;
	unsigned char *result = calloc(n, (sizeof(unsigned char)));
	for (i=0; i<size; i++) {
		result[i+(n-size)] = block[i];
	}
	return result;
}


char *blockToChar(unsigned char *block, int bitsSize) {
	int i, j;
	int numberOfBytes = bitsSize/8;
	char *result = calloc((numberOfBytes*2)+1, sizeof(char));
	result[numberOfBytes*2] = '\0';
	j = 0;
	for (i=0; i<numberOfBytes; i++) {
		sprintf(&result[j], "%x", (block[i] & 0xf0)>>4);
		sprintf(&result[j+1], "%x", (block[i] & 0x0f));
		j+=2;
	}
	return(result);
}


unsigned char *AESencrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[16];
	unsigned char *cipher = calloc(16, (sizeof(unsigned char)));
	AES_KEY expandKey;
	int i = 0;
	key[0]=0b01000000; for (i=1; i<16; i++) { key[i] = 0; }
	AES_set_encrypt_key(key, 128, &expandKey);
	AES_encrypt(clear, cipher, &expandKey);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s ", cpt, blockToChar(clear, 128), blockToChar(key, 128), blockToChar(cipher, 128));
	return(cipher);
}


unsigned char *BlowfishEncrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[16];
	unsigned char *cipher =  calloc(8, (sizeof(unsigned char)));
	BF_KEY expandKey;
	int i = 0;
	key[0]=0b10000000; for (i=1; i<16; i++) { key[i] = 0; }
	BF_set_key(&expandKey, 16, key); //128 bits key
	BF_ecb_encrypt(clear, cipher, &expandKey, BF_ENCRYPT);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s\t", cpt, blockToChar(clear, 64), blockToChar(key, 128), blockToChar(cipher, 64));
	return(cipher);
}


unsigned char *DESencrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[8];
	unsigned char *cipher =  calloc(8, (sizeof(unsigned char)));
	DES_cblock clear_des;
	DES_cblock cipher_des;
	int i = 0;
	memcpy(clear_des, clear, 8);
	DES_key_schedule expandKey;
	key[0]=0b01000000; for (i=1; i<8; i++) { key[i] = 0; }
	DES_set_key(&key, &expandKey);
	DES_ecb_encrypt(&clear_des, &cipher_des, &expandKey, DES_ENCRYPT);
	memcpy(cipher, cipher_des, 8);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s\t", cpt, blockToChar(clear, 64), blockToChar(key, 64), blockToChar(cipher, 64));
	return(cipher);
}


unsigned char *tripleDESencrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key1[8], key2[8], key3[8];
	unsigned char *cipher =  calloc(8, (sizeof(unsigned char)));
	DES_cblock clear_des;
	DES_cblock cipher_des;
	int i = 0;
	memcpy(clear_des, clear, 8);
	DES_key_schedule expandKey1;
	DES_key_schedule expandKey2;
	DES_key_schedule expandKey3;
	key1[0]=0b10000000; for (i=1; i<8; i++) { key1[i] = 0; }
	for (i=0; i<8; i++) { key2[i] = 0; }
	for (i=0; i<8; i++) { key3[i] = 0b11111111; }
	DES_set_key(&key1, &expandKey1);
	DES_set_key(&key2, &expandKey2);
	DES_set_key(&key3, &expandKey3);
	DES_ecb3_encrypt(&clear_des, &cipher_des, &expandKey1, &expandKey2, &expandKey3, DES_ENCRYPT);
	memcpy(cipher, cipher_des, 8);
	printf("%lu\tclear: %s,\tkeys: %s %s %s,\tcipher: %s\t", cpt, blockToChar(clear, 64), blockToChar(key1, 64), blockToChar(key2, 64), blockToChar(key3, 64), blockToChar(cipher, 64));
	return(cipher);
}


unsigned char *RC4encrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[16];
	unsigned char *cipher = calloc(16, (sizeof(unsigned char)));
	RC4_KEY rc4_key;
	unsigned int i = 0;
	key[0]=0b10000000; for (i=1; i<16; i++) { key[i] = 0; }
	RC4_set_key(&rc4_key, 16, key);
	RC4(&rc4_key, 16, clear, cipher);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s ", cpt, blockToChar(clear, 128), blockToChar(key, 128), blockToChar(cipher, 128));
	return(cipher);
}


void generateFile(void) {
	unsigned long i = 0;
	unsigned long base = 2;
	unsigned long exponent = 0;
	unsigned char *clear = NULL;
	unsigned char *cipher = NULL;
	if ((algo==1) | (algo==5)) { // AES or RC4
		exponent = 105; // must be < 128
		cipher = calloc(16, sizeof(unsigned char));
	}
	if ((algo==2) | (algo==3) | (algo==4)) { // Blowfish, DES, 3DES
		exponent = 50; // must be < 64
		cipher = calloc(8, sizeof(unsigned char));
	}
	BIGNUM *bn_base = BN_new();
	BIGNUM *bn_exponent = BN_new();
	BIGNUM *bn_clear = BN_new();
	BIGNUM *bn_cipher = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		BN_set_word(bn_base, base);
		BN_set_word(bn_exponent, exponent);
		BN_exp(bn_clear, bn_base, bn_exponent, ctx); // bn_clear = bn_base^bn_exponent
		for (i=1; i<iterations; i++) {
			BN_add_word(bn_clear, 1); // add 1 to the block value
			if ((algo==1) | (algo==5)) { clear = calloc(16, sizeof(unsigned char)); }
			if ((algo==2) | (algo==3) | (algo==4)) { clear = calloc(8, sizeof(unsigned char)); }
			BN_bn2bin(bn_clear, clear);
			if (algo == 1) {
				cipher = AESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), 16), i);
				bn_cipher = BN_bin2bn(cipher,16, NULL);
			}
			if (algo == 2) {
				cipher = BlowfishEncrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), 8), i);
				bn_cipher = BN_bin2bn(cipher,8, NULL);
			}
			if (algo == 3) {
				cipher = DESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), 8), i);
				bn_cipher = BN_bin2bn(cipher,8, NULL);
			}
			if (algo == 4) {
				cipher = tripleDESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), 8), i);
				bn_cipher = BN_bin2bn(cipher,8, NULL);
			}
			if (algo == 5) {
				cipher = RC4encrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), 16), i);
				bn_cipher = BN_bin2bn(cipher,16, NULL);
			}
			BN_print_fp(fic, bn_cipher);
			printf("(%s)\n", BN_bn2dec(bn_cipher));
			fprintf(fic, "\n");
		}
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
	BN_clear_free(bn_base);
	BN_clear_free(bn_exponent);
	BN_clear_free(bn_clear);
	BN_clear_free(bn_cipher);
	BN_CTX_free(ctx);
	free(clear);
	free(cipher);
}


int main(int argc, char *argv[]) {
	switch (argc) {
		case 3:
			if (strcmp(argv[2], "aes") == 0) {
				algo = 1;
			} else if (strcmp(argv[2], "blowfish") == 0) {
				algo = 2;
			} else if (strcmp(argv[2], "des") == 0) {
				algo = 3;
			} else if (strcmp(argv[2], "3des") == 0) {
				algo = 4;
			} else if (strcmp(argv[2], "rc4") == 0) {
				algo = 5;
			} else {
				usage();
				exit(EXIT_FAILURE);
			}
			iterations = atol(argv[1]);
			generateFile();
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;	
		}
}
