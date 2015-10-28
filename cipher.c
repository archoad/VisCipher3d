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
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>
#include <openssl/md4.h>

#define couleur(param) printf("\033[%sm",param)


static unsigned long iterations;


static int algo = 0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- cipher -- (c) 2014\n\n");
	couleur("0");
	printf("Syntaxe: cipher <num> <algo>\n");
	printf("\t<num> -> sample size\n");
	printf("\t<algo> -> 'aes', 'blowfish', '3des', 'des', 'rc4', 'md4', 'md5' or 'base64'\n");
}


unsigned char *putToNbytesBlock(unsigned char *block, int size, int n) {
	int i;
	unsigned char *result = calloc(n, (sizeof(unsigned char)));
	for (i=0; i<size; i++) {
		result[i+(n-size)] = block[i];
	}
	return result;
}


BIGNUM* generateNBitsBlock(BIGNUM *block, int n) {
	int i = 0;
	for (i=0; i<n; i++) {
		BN_clear_bit(block, i);
	}
	return(block);
}


char *blockToString(unsigned char *block, int bitsSize) {
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


unsigned char *MD4Hash(unsigned char *text, unsigned long cpt) {
	unsigned char *digest = calloc(MD4_DIGEST_LENGTH, (sizeof(unsigned char)));
	MD4(text, 16, digest);
	printf("%lu\ttext: %s,\tMD4 digest: %s\n", cpt, blockToString(text, 128), blockToString(digest, 128));
	return(digest);
}


unsigned char *MD5Hash(unsigned char *text, unsigned long cpt) {
	unsigned char *digest = calloc(MD5_DIGEST_LENGTH, (sizeof(unsigned char)));
	MD5(text, 16, digest);
	printf("%lu\ttext: %s,\tMD5 digest: %s\n", cpt, blockToString(text, 128), blockToString(digest, 128));
	return(digest);
}


unsigned char *AESencrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[16];
	unsigned char *cipher = calloc(16, (sizeof(unsigned char)));
	AES_KEY expandKey;
	int i = 0;
	key[0]=0b10000000; for (i=1; i<16; i++) { key[i] = 0; }
	AES_set_encrypt_key(key, 128, &expandKey);
	AES_encrypt(clear, cipher, &expandKey);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToString(clear, 128), blockToString(key, 128), blockToString(cipher, 128));
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
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToString(clear, 64), blockToString(key, 128), blockToString(cipher, 64));
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
	key[0]=0b10000000; for (i=1; i<8; i++) { key[i] = 0; }
	DES_set_key(&key, &expandKey);
	DES_ecb_encrypt(&clear_des, &cipher_des, &expandKey, DES_ENCRYPT);
	memcpy(cipher, cipher_des, 8);
	printf("%lu\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToString(clear, 64), blockToString(key, 64), blockToString(cipher, 64));
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
	for (i=0; i<8; i++) { key2[i] = 0b10101010; }
	for (i=0; i<8; i++) { key3[i] = 0b11111111; }
	DES_set_key(&key1, &expandKey1);
	DES_set_key(&key2, &expandKey2);
	DES_set_key(&key3, &expandKey3);
	DES_ecb3_encrypt(&clear_des, &cipher_des, &expandKey1, &expandKey2, &expandKey3, DES_ENCRYPT);
	memcpy(cipher, cipher_des, 8);
	printf("%lu\tclear: %s,\tkeys: %s %s %s,\tcipher: %s\n", cpt, blockToString(clear, 64), blockToString(key1, 64), blockToString(key2, 64), blockToString(key3, 64), blockToString(cipher, 64));
	return(cipher);
}


unsigned char *RC4encrypt(unsigned char *clear, unsigned long cpt) {
	unsigned char key[8];
	unsigned char *cipher = calloc(16, (sizeof(unsigned char)));
	unsigned char *decipher = calloc(16, (sizeof(unsigned char)));
	RC4_KEY rc4_key;
	unsigned int i = 0;
	//key[7]=0b00001111; for (i=0; i<7; i++) { key[i] = 0b00001111; }
	key[7]=0b00000001; for (i=0; i<7; i++) { key[i] = 0b00000001; }
	RC4_set_key(&rc4_key, 8, key);
	RC4(&rc4_key, 16, clear, cipher);

	RC4_set_key(&rc4_key, 8, key);
	RC4(&rc4_key, 16, cipher, decipher);
	printf("%lu\tclear: %s, key: %s, cipher: %s, decipher: %s\n", cpt, blockToString(clear, 128), blockToString(key, 64), blockToString(cipher, 128), blockToString(decipher, 128));
	return(cipher);
}


unsigned char *base64encode(unsigned char *clear, unsigned long cpt) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	unsigned char *cipher = NULL;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);

	BIO_write(b64, clear, sizeof(clear));
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	cipher = calloc(bptr->length, sizeof(unsigned char));
	memcpy(cipher, bptr->data, bptr->length-1);
	cipher[bptr->length-1] = 0;

	printf("%lu\tclear: %s, cipher: %s(%s)\n", cpt, blockToString(clear, 64), cipher, blockToString(cipher, 128));
	BIO_free_all(b64);
	return(cipher);
}


void generateFile(char *a) {
	int clearSizeInByte = 0, keySizeInByte = 0, modifiedBit = 0;
	unsigned long i = 0;
	unsigned char *cipher = NULL;
	unsigned char *clear = NULL;
	BIGNUM *bn_clear = BN_new();
	BIGNUM *bn_cipher = BN_new();
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		if ((algo == 1 /*AES*/) | (algo == 5 /*RC4*/) | (algo == 7 /*MD4*/) | (algo == 8 /*MD5*/)) {
			clearSizeInByte = 16;
			keySizeInByte = 16;
			modifiedBit = 100; // must be < 128
		} else if (algo == 6 /*base64*/) {
			clearSizeInByte = 8;
			keySizeInByte = 16;
			modifiedBit = 50; // must be < 64
		} else {
			clearSizeInByte = 8;
			keySizeInByte = 8;
			modifiedBit = 50; // must be < 64
		}
		generateNBitsBlock(bn_clear, clearSizeInByte*8);
		BN_set_bit(bn_clear, modifiedBit); 
		clear = calloc(clearSizeInByte, sizeof(unsigned char));
		cipher = calloc(keySizeInByte, sizeof(unsigned char));
		printf("INFO: %s -> clear block size: %d bits\tcipher block size: %d bits\n", a, clearSizeInByte*8, keySizeInByte*8);

		for (i=1; i<iterations; i++) {
			BN_add_word(bn_clear, 1); // add 1 to the block value
			BN_bn2bin(bn_clear, clear);
			if (algo == 1 /*AES 128*/) {
				cipher = AESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 2 /*Blowfish*/) {
				cipher = BlowfishEncrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 3 /*DES*/) {
				cipher = DESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 4 /*3DES*/) {
				cipher = tripleDESencrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 5 /*RC4*/) {
				cipher = RC4encrypt(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 6 /*base64*/) {
				cipher = base64encode(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 7 /*MD4*/) {
				cipher = MD4Hash(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			if (algo == 8 /*MD5*/) {
				cipher = MD5Hash(putToNbytesBlock(clear, BN_num_bytes(bn_clear), clearSizeInByte), i);
			}
			bn_cipher = BN_bin2bn(cipher, keySizeInByte, NULL);
			BN_print_fp(fic, bn_cipher);
			fprintf(fic, "\n");
		}
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
	BN_clear_free(bn_clear);
	BN_clear_free(bn_cipher);
	free(clear);
	free(cipher);
}


int main(int argc, char *argv[]) {
	switch (argc) {
		case 3:
			if (strncmp(argv[2], "aes", 3) == 0) { algo = 1; }
			else if (strncmp(argv[2], "blowfish", 8) == 0) { algo = 2; }
			else if (strncmp(argv[2], "des", 3) == 0) { algo = 3; }
			else if (strncmp(argv[2], "3des", 4) == 0) { algo = 4; }
			else if (strncmp(argv[2], "rc4", 3) == 0) { algo = 5; }
			else if (strncmp(argv[2], "base64", 6) == 0) { algo = 6; }
			else if (strncmp(argv[2], "md4", 3) == 0) { algo = 7; }
			else if (strncmp(argv[2], "md5", 3) == 0) { algo = 8; }
			else {
				usage();
				exit(EXIT_FAILURE);
			}
			iterations = atol(argv[1])+1;
			generateFile(argv[2]);
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;	
		}
}
