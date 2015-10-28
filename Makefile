# définition des cibles particulières
.PHONY: clean, mrproper
  
# désactivation des règles implicites
.SUFFIXES:

UNAME_S:=$(shell uname -s)

CC=gcc
#CL=gcc
CL=gcc
STRIP=strip
CFLAGS= -O3 -Wall -W -Wstrict-prototypes -Werror
ifeq ($(UNAME_S),Linux)
	IFLAGSDIR= -I/usr/include
	LFLAGSDIR= -L/usr/lib
	COMPIL=$(CC)
endif
ifeq ($(UNAME_S),Darwin)
	IFLAGSDIR= -I/opt/local/include
	LFLAGSDIR= -L/opt/local/lib
	COMPIL=$(CL)
endif
GDB_FLAGS= -ggdb
GL_FLAGS= -lGL -lGLU -lglut
MATH_FLAGS= -lm
CRYPTO_FLAGS= -lcrypto
PNG_FLAGS= -lpng

all: dest_sys visCipherCmp3d visCipher3d cipher vigenere

visCipherCmp3d: visCipherCmp3d.c
	$(COMPIL) $(CFLAGS) $(IFLAGSDIR) $(LFLAGSDIR) $(MATH_FLAGS) $(GL_FLAGS) $(PNG_FLAGS) $(CRYPTO_FLAGS) $< -o $@
	@$(STRIP) $@

visCipher3d: visCipher3d.c
	$(COMPIL) $(CFLAGS) $(IFLAGSDIR) $(LFLAGSDIR) $(MATH_FLAGS) $(GL_FLAGS) $(PNG_FLAGS) $(CRYPTO_FLAGS) $< -o $@
	@$(STRIP) $@

cipher: cipher.c
	$(COMPIL) $(CFLAGS) $(IFLAGSDIR) $(LFLAGSDIR) $(CRYPTO_FLAGS) $(MATH_FLAGS) $< -o $@
	@$(STRIP) $@

vigenere: vigenere.c
	$(COMPIL) $(CFLAGS) $(IFLAGSDIR) $(LFLAGSDIR) $(MATH_FLAGS) $< -o $@
	@$(STRIP) $@

dest_sys:
	@echo "Destination system:" $(UNAME_S)

clean:
	@rm -f visCipherCmp3d
	@rm -f visCipher3d
	@rm -f cipher
	@rm -f vigenere
