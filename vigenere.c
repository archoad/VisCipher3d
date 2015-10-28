/*vigenere
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


#define couleur(param) printf("\033[%sm",param)


static int clearLen = 4;


void usage(void) {
	couleur("31");
	printf("Michel Dubois -- vigenere -- (c) 2014\n\n");
	couleur("0");
	printf("Syntaxe: vigenere <key>\n");
	printf("\t<key> -> key under the form ABCD\n");
}


char *vigenereCipher(char *clear, char *key) {
	int i = 0, keySize = strlen(key);
	char *cipher = malloc(clearLen * sizeof(char));

	for (i=0; i<clearLen-1; i++) {
		cipher[i] = 'A' + (clear[i] - 'A' + key[i % keySize] - 'A') % 26;
	}
	cipher[clearLen-1] = '\0';
	return(cipher);
}


char *vigenereDeCipher(char *cipher, char *key) {
	int i = 0, keySize = strlen(key);
	char *clear = malloc(clearLen * sizeof(char));

	for (i=0; i<clearLen-1; i++) {
		clear[i] = 'A' + (cipher[i] - key[i % keySize] + 26) % 26;
	}
	clear[clearLen-1] = '\0';
	return(clear);
}


char *blockToDecimal(char *block) {
	int len = strlen(block);
	char *result = malloc(len * 2 * sizeof(char));
	sprintf(result, "%d%d%d%d%d%d%d%d", block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7]);
	result[len*2] = '\0';
	return(result);
}


void generateFile(char *key) {
	int i, j, k, cpt = 0;
	char *clear = malloc(clearLen * sizeof(char));
	char *cipher = malloc(clearLen * sizeof(char));
	FILE *fic = fopen("result.dat", "w");

	if (fic != NULL) {
		printf("INFO: file create\n");
		for (i=0; i<26; i++) {
			for (j=0; j<26; j++) {
				for (k=0; k<26; k++) {
							clear[0] = i + 65;
							clear[1] = j + 65;
							clear[2] = k + 65;
							clear[clearLen] = '\0';
							cipher = vigenereCipher(clear, key);
							printf("%d -> %s, %s, %s (%s), %s\n", cpt, clear, key, cipher, blockToDecimal(cipher), vigenereDeCipher(cipher, key));
							fprintf(fic, "%s\n", blockToDecimal(cipher));
							cpt ++;
				}
			}
		}
		free(clear);
		free(cipher);
		fclose(fic);
		printf("INFO: file close\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
}


int main(int argc, char *argv[]) {
	switch (argc) {
		case 2:
			generateFile(argv[1]);
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;	
		}
}
