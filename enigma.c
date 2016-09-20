/*enigma
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

/* enigma simulation and bombe, harald schmidl, april 1998
the encoding scheme uses code from Fauzan Mirza's
3 rotor German Enigma simulation */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define TO 'E'

/* Rotor wirings */
char rotor[5][26]= {
	/* Input "ABCDEFGHIJKLMNOPQRSTUVWXYZ" */
	/* 1: */ "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
	/* 2: */ "AJDKSIRUXBLHWTMCQGZNPYFVOE",
	/* 3: */ "BDFHJLCPRTXVZNYEIWGAKMUSQO",
	/* 4: */ "ESOVPZJAYQUIRHXLNFTGKDCMWB",
	/* 5: */ "VZBRGITYUPSDNHLXAWMJQOFECK"
};

char ref[26]="YRUHQSLDPXNGOKMIEBFZCWVJAT";

char notch[5]="QEVJZ";

typedef struct P {
	char order[3];/*={ 1, 2, 3 };*/
	char rings[3];/*={ 'A','A','A' };*/
	char pos[3];/*={ 'A','A','A' };*/
	char plug[10];/*="AMTE";*/
} params;

static int blockLen = 6;

char scramble(char c, params *p) {
	int i, j, flag = 0;
	c=toupper(c);
	if (!isalpha(c))
		return -1;

	/* Step up first rotor */
	p->pos[0]++;
	if (p->pos[0]>'Z')
		p->pos[0] -= 26;

	/* Check if second rotor reached notch last time */
	if (flag) {
		/* Step up both second and third rotors */
		p->pos[1]++;
		if (p->pos[1]>'Z')
			p->pos[1] -= 26;
		p->pos[2]++;
		if (p->pos[2]>'Z')
			p->pos[2] -= 26;
		flag=0;
	}

	/*  Step up second rotor if first rotor reached notch */
	if (p->pos[0]==notch[p->order[0]-1]) {
		p->pos[1]++;
		if (p->pos[1]>'Z')
			p->pos[1] -= 26;
		/* Set flag if second rotor reached notch */
		if (p->pos[1]==notch[p->order[1]-1])
			flag=1;
	}

	/*  Swap pairs of letters on the plugboard */
	for (i=0; p->plug[i]; i+=2) {
		if (c==p->plug[i])
			c=p->plug[i+1];
		else if (c==p->plug[i+1])
			c=p->plug[i];
	}

	/*  Rotors (forward) */
	for (i=0; i<3; i++) {
		c += p->pos[i]-'A';
		if (c>'Z')
			c -= 26;

		c -= p->rings[i]-'A';
		if (c<'A')
			c += 26;

		c=rotor[p->order[i]-1][c-'A'];

		c += p->rings[i]-'A';
		if (c>'Z')
			c -= 26;

		c -= p->pos[i]-'A';
		if (c<'A')
			c += 26;
	}

	/*  Reflecting rotor */
	c=ref[c-'A'];

	/*  Rotors (reverse) */
	for (i=3; i; i--) {
		c += p->pos[i-1]-'A';
		if (c>'Z')
			c -= 26;

		c -= p->rings[i-1]-'A';
		if (c<'A')
			c += 26;

		for (j=0; j<26; j++)
			if (rotor[p->order[i-1]-1][j]==c)
				break;
		c=j+'A';

		c += p->rings[i-1]-'A';
		if (c>'Z')
			c -= 26;

		c -= p->pos[i-1]-'A';
		if (c<'A')
			c += 26;
	}

	/*  Plugboard */
	for (i=0; p->plug[i]; i+=2) {
		if (c==p->plug[i])
			c=p->plug[i+1];
		else if (c==p->plug[i+1])
			c=p->plug[i];
	}
	return c;
}


char* enigma(char *in, params *p) {
	int j;
	char *out = calloc(blockLen, sizeof(char));
	for (j=0; j<(int)strlen(in); j++)
		out[j] = scramble(in[j], p);
	out[j] = '\0';
	return out;
}


void initParams(params *p) {
	int i;

	for (i = 0; i < 3; i++) {
		p->order[i] = i + 1;
		p->rings[i] = 'A';
		p->pos[i] = 'A';
	}
	strcpy(p->plug, "");

	printf("Wheels %d %d %d, Start %c %c %c, Rings %c %c %c, Stecker \"%s\"\n",
		p->order[0], p->order[1], p->order[2],
		p->pos[0], p->pos[1], p->pos[2],
		p->rings[0], p->rings[1], p->rings[2], p->plug);
}


char *blockToHex(char *block) {
	char *result = calloc((blockLen*2)+1, sizeof(char));
	sprintf(result, "%02x%02x%02x%02x%02x", block[0], block[1], block[2], block[3], block[4]);
	return(result);
}


void generateFile(void) {
	params p;
	int i, j, k, l, m, cpt = 0;
	char *clear = malloc(blockLen * sizeof(char));
	char *cipher = malloc(blockLen * sizeof(char));

	FILE *fic = fopen("result.dat", "w");
	if (fic != NULL) {
		printf("INFO: file create\n");
		initParams(&p);
		for (i=0; i<5; i++) {
			for (j=0; j<26; j++) {
				for (k=0; k<26; k++) {
					for (l=0; l<26; l++) {
						for (m=0; m<26; m++) {
							clear[0] = i + 65;
							clear[1] = j + 65;
							clear[2] = k + 65;
							clear[3] = l + 65;
							clear[4] = m + 65;
							clear[blockLen] = '\0';
							cipher = enigma(clear, &p);
							printf("%d: %s -> %s (%s)\n", cpt, clear, cipher, blockToHex(cipher));
							fprintf(fic, "%s\n", blockToHex(cipher));
							cpt ++;
						}
					}
				}
			}
		}
		free(clear);
		free(cipher);
		fclose(fic);
		printf("INFO: file close\n\n");
	} else {
		printf("INFO: open error\n");
		exit(EXIT_FAILURE);
	}
}


void testCipher(void) {
	params p;
	char *clear = NULL;
	char *cipher = NULL;

	initParams(&p);
	clear = "AAAAA";
	cipher = enigma(clear, &p);
	printf("%s -> %s (%s)\n", clear, cipher, blockToHex(cipher));
	clear = "EZZZZ";
	cipher = enigma(clear, &p);
	printf("%s -> %s (%s)\n", clear, cipher, blockToHex(cipher));
}


int main(void) {
	generateFile();
	testCipher();
	return 1;
}
