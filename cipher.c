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
#include <openssl/sha.h>

#define couleur(param) printf("\033[%sm",param)


static unsigned long iterations;

static int algo = 0;

static int clearSizeInByte = 0, keySizeInByte = 0, cipherSizeInByte = 0;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- cipher -- (c) 2014\n\n");
	couleur("0");
	printf("Syntaxe: cipher <num> <algo>\n");
	printf("\t<num> -> sample size\n");
	printf("\t<algo> -> 'aes', 'blowfish', '3des', 'des', 'rc4', 'md4', 'md5', 'sha1', 'sha256' or 'base64'\n");
}


unsigned char assignByte(char num[8]) {
	int i = 0;
	unsigned char result = 0;
	for (i=0; i<8; ++i) {
		result |= (num[i] == '1') << (7 - i);
	}
	return(result);
}


void integerToByte(unsigned int val, char bits[8]) {
	int i=0;
	for (i=7; i>=0; i--) {
		if ((val >> i) & 1) {
			bits[7-i] = '1';
		} else {
			bits[7-i] = '0';
		}
	}
}


char *blockToHex(unsigned char *block, int bytesSize) {
	int i, j;
	char *result = calloc((bytesSize*2)+1, sizeof(char));
	result[bytesSize*2] = '\0';
	j = 0;
	for (i=0; i<bytesSize; i++) {
		sprintf(&result[j], "%x", (block[i] & 0xf0)>>4);
		sprintf(&result[j+1], "%x", (block[i] & 0x0f));
		j+=2;
	}
	return(result);
}


unsigned char* generateNBytesBlock(unsigned int iteration, int bytesSize) {
	char bits[8] = "00000000";
	unsigned char *block = calloc(bytesSize, (sizeof(block)));
	if (iteration < 256) {
		integerToByte(iteration, bits);
		block[bytesSize-1] = assignByte(bits);
	}
	if ((iteration >= 256) && (iteration < 65536)) {
		integerToByte(iteration, bits);
		block[bytesSize-1] = assignByte(bits);
		integerToByte(iteration>>8, bits);
		block[bytesSize-2] = assignByte(bits);
	}
	if ((iteration >= 65536) && (iteration < 16777216)) {
		integerToByte(iteration, bits);
		block[bytesSize-1] = assignByte(bits);
		integerToByte(iteration>>8, bits);
		block[bytesSize-2] = assignByte(bits);
		integerToByte(iteration>>16, bits);
		block[bytesSize-3] = assignByte(bits);
	}
	if ((iteration >= 16777216) && (iteration < 4294967295)) {
		integerToByte(iteration, bits);
		block[bytesSize-1] = assignByte(bits);
		integerToByte(iteration>>8, bits);
		block[bytesSize-2] = assignByte(bits);
		integerToByte(iteration>>16, bits);
		block[bytesSize-3] = assignByte(bits);
		integerToByte(iteration>>24, bits);
		block[bytesSize-4] = assignByte(bits);
	}
	return(block);
}


unsigned char *AESencrypt(unsigned char *clear, unsigned int cpt) {
	unsigned char key[keySizeInByte];
	unsigned char *cipher = calloc(cipherSizeInByte, (sizeof(unsigned char)));
	AES_KEY expandKey;
	int i = 0;
	key[0] = assignByte("00000001");
	for (i=1; i<keySizeInByte; i++) { key[i] = assignByte("00000000"); }
	AES_set_encrypt_key(key, keySizeInByte*8, &expandKey);
	AES_encrypt(clear, cipher, &expandKey);
	printf("%d\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToHex(clear, clearSizeInByte), blockToHex(key, keySizeInByte), blockToHex(cipher, cipherSizeInByte));
	return(cipher);
}


unsigned char *BlowfishEncrypt(unsigned char *clear, unsigned int cpt) {
	unsigned char key[keySizeInByte];
	unsigned char *cipher =  calloc(cipherSizeInByte, (sizeof(unsigned char)));
	BF_KEY expandKey;
	int i = 0;
	key[0] = assignByte("00000001");
	for (i=1; i<keySizeInByte; i++) { key[i] = assignByte("00000000"); }
	BF_set_key(&expandKey, keySizeInByte, key); //128 bits key
	BF_ecb_encrypt(clear, cipher, &expandKey, BF_ENCRYPT);
	printf("%d\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToHex(clear, clearSizeInByte), blockToHex(key, keySizeInByte), blockToHex(cipher, cipherSizeInByte));
	return(cipher);
}


unsigned char *DESencrypt(unsigned char *clear, unsigned int cpt) {
	unsigned char key[keySizeInByte];
	unsigned char *cipher =  calloc(cipherSizeInByte, (sizeof(unsigned char)));
	DES_cblock clear_des;
	DES_cblock cipher_des;
	int i = 0;
	memcpy(clear_des, clear, clearSizeInByte);
	DES_key_schedule expandKey;
	key[0] = assignByte("00000001");
	for (i=1; i<keySizeInByte; i++) { key[i] = assignByte("00000000"); }
	DES_set_key(&key, &expandKey);
	DES_ecb_encrypt(&clear_des, &cipher_des, &expandKey, DES_ENCRYPT);
	memcpy(cipher, cipher_des, cipherSizeInByte);
	printf("%d\tclear: %s,\tkey: %s,\tcipher: %s\n", cpt, blockToHex(clear, clearSizeInByte), blockToHex(key, keySizeInByte), blockToHex(cipher, cipherSizeInByte));
	return(cipher);
}


unsigned char *tripleDESencrypt(unsigned char *clear, unsigned int cpt) {
	unsigned char key1[keySizeInByte], key2[keySizeInByte], key3[keySizeInByte];
	unsigned char *cipher =  calloc(cipherSizeInByte, (sizeof(unsigned char)));
	DES_cblock clear_des;
	DES_cblock cipher_des;
	int i = 0;
	memcpy(clear_des, clear, clearSizeInByte);
	DES_key_schedule expandKey1;
	DES_key_schedule expandKey2;
	DES_key_schedule expandKey3;
	key1[0] = assignByte("00000001");
	for (i=1; i<keySizeInByte; i++) { key1[i] = assignByte("00000000"); }
	key2[0] = assignByte("00000011");
	for (i=1; i<keySizeInByte; i++) { key2[i] = assignByte("00000000"); }
	key3[0] = assignByte("00000111");
	for (i=1; i<keySizeInByte; i++) { key3[i] = assignByte("00000000"); }
	DES_set_key(&key1, &expandKey1);
	DES_set_key(&key2, &expandKey2);
	DES_set_key(&key3, &expandKey3);
	DES_ecb3_encrypt(&clear_des, &cipher_des, &expandKey1, &expandKey2, &expandKey3, DES_ENCRYPT);
	memcpy(cipher, cipher_des, cipherSizeInByte);
	printf("%d\tclear: %s,\tkeys: %s %s %s,\tcipher: %s\n", cpt, blockToHex(clear, clearSizeInByte), blockToHex(key1, keySizeInByte), blockToHex(key2, keySizeInByte), blockToHex(key3, keySizeInByte), blockToHex(cipher, cipherSizeInByte));
	return(cipher);
}


unsigned char *RC4encrypt(unsigned char *clear, unsigned int cpt) {
	unsigned char key[keySizeInByte];
	unsigned char *cipher = calloc(cipherSizeInByte, (sizeof(unsigned char)));
	unsigned char *decipher = calloc(clearSizeInByte, (sizeof(unsigned char)));
	RC4_KEY rc4_key;
	int i = 0;
	key[0] = assignByte("00000001");
	for (i=1; i<keySizeInByte; i++) { key[i] = assignByte("00000000"); }
	RC4_set_key(&rc4_key, keySizeInByte, key);
	RC4(&rc4_key, cipherSizeInByte, clear, cipher);

	RC4_set_key(&rc4_key, keySizeInByte, key);
	RC4(&rc4_key, clearSizeInByte, cipher, decipher);
	printf("%d\tclear: %s, key: %s, cipher: %s, decipher: %s\n", cpt, blockToHex(clear, clearSizeInByte), blockToHex(key, keySizeInByte), blockToHex(cipher, cipherSizeInByte), blockToHex(decipher, clearSizeInByte));
	return(cipher);
}


unsigned char *base64encode(unsigned char *clear, unsigned int cpt) {
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

	printf("%d\tclear: %s, cipher: %s(%s)\n", cpt, blockToHex(clear, clearSizeInByte), cipher, blockToHex(cipher, keySizeInByte));
	BIO_free_all(b64);
	return(cipher);
}


unsigned char *MD4Hash(unsigned char *text, unsigned int cpt) {
	unsigned char *digest = calloc(MD4_DIGEST_LENGTH, (sizeof(unsigned char)));
	MD4(text, clearSizeInByte, digest);
	printf("%d\ttext: %s,\tMD4 digest: %s\n", cpt, blockToHex(text, clearSizeInByte), blockToHex(digest, MD4_DIGEST_LENGTH));
	return(digest);
}


unsigned char *MD5Hash(unsigned char *text, unsigned int cpt) {
	unsigned char *digest = calloc(MD5_DIGEST_LENGTH, (sizeof(unsigned char)));
	MD5(text, clearSizeInByte, digest);
	printf("%d\ttext: %s,\tMD5 digest: %s\n", cpt, blockToHex(text, clearSizeInByte), blockToHex(digest, MD5_DIGEST_LENGTH));
	return(digest);
}


unsigned char *SHA1Hash(unsigned char *text, unsigned int cpt) {
	unsigned char *digest = calloc(SHA_DIGEST_LENGTH, (sizeof(unsigned char)));
	SHA1(text, clearSizeInByte, digest);
	printf("%d\ttext: %s,\tSHA1 digest: %s\n", cpt, blockToHex(text, clearSizeInByte), blockToHex(digest, SHA_DIGEST_LENGTH));
	return(digest);
}


unsigned char *SHA256Hash(unsigned char *text, unsigned int cpt) {
	unsigned char *digest = calloc(SHA256_DIGEST_LENGTH, (sizeof(unsigned char)));
	SHA256(text, clearSizeInByte, digest);
	printf("%d\ttext: %s,\tSHA256 digest: %s\n", cpt, blockToHex(text, clearSizeInByte), blockToHex(digest, SHA256_DIGEST_LENGTH));
	return(digest);
}


void generateFile(char *a) {
	unsigned int i = 0;
	unsigned char *cipher = NULL;
	unsigned char *clear = NULL;
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		if (algo == 1 /*AES*/) { clearSizeInByte = 16; keySizeInByte = 16; cipherSizeInByte = 16; }
		if (algo == 2 /*Blowfish*/) { clearSizeInByte = 8; keySizeInByte = 8; cipherSizeInByte = 8; }
		if (algo == 3 /*DES*/) { clearSizeInByte = 8; keySizeInByte = 7; cipherSizeInByte = 8; }
		if (algo == 4 /*3DES*/) { clearSizeInByte = 8; keySizeInByte = 7; cipherSizeInByte = 8; }
		if (algo == 5 /*RC4*/) { clearSizeInByte = 16; keySizeInByte = 8; cipherSizeInByte = 16; }
		if (algo == 6 /*base64*/) { clearSizeInByte = 8; keySizeInByte = 16; }
		if (algo == 7 /*MD4*/) { clearSizeInByte = 16; }
		if (algo == 8 /*MD5*/) { clearSizeInByte = 16; }
		if (algo == 9 /*SHA1*/) { clearSizeInByte = 16; }
		if (algo == 10 /*SHA256*/) { clearSizeInByte = 16; }

		cipher = (unsigned char*)calloc(keySizeInByte, sizeof(unsigned char));
		printf("INFO: %s -> clear block size: %d bits, cipher block size: %d bits\n", a, clearSizeInByte*8, keySizeInByte*8);

		for (i=1; i<iterations; i++) {
			clear = generateNBytesBlock(i, clearSizeInByte);
			if (algo == 1 /*AES 128*/) { cipher = AESencrypt(clear, i); }
			if (algo == 2 /*Blowfish*/) { cipher = BlowfishEncrypt(clear, i); }
			if (algo == 3 /*DES*/) { cipher = DESencrypt(clear, i); }
			if (algo == 4 /*3DES*/) { cipher = tripleDESencrypt(clear, i); }
			if (algo == 5 /*RC4*/) { cipher = RC4encrypt(clear, i); }
			if (algo == 6 /*base64*/) { cipher = base64encode(clear, i); }
			if (algo == 7 /*MD4*/) { cipher = MD4Hash(clear, i); }
			if (algo == 8 /*MD5*/) { cipher = MD5Hash(clear, i); }
			if (algo == 9 /*SHA1*/) { cipher = SHA1Hash(clear, i); }
			if (algo == 10 /*SHA256*/) { cipher = SHA256Hash(clear, i); }
			fprintf(fic, "%s", blockToHex(cipher, keySizeInByte));
			fprintf(fic, "\n");
		}
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
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
			else if (strncmp(argv[2], "sha1", 4) == 0) { algo = 9; }
			else if (strncmp(argv[2], "sha256", 6) == 0) { algo = 10; }
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
