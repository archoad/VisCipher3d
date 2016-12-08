VisCipher3d
===========
Suite of programs for ciphering and visualising in 3D environment.

To compile programs: `make`

# cipher

Generates a `num` sample size sequence of first integers and ciphers it with one of these algorithms: `aes`, `blowfish`, `3des`, `des`, `rc4`, `md4`, `md5` and `base64`.

The result is a file `result.dat` containing the ciphered 
sequence.

# vigenere

Generates the sequence off all combinations of three letters and ciphers it with the vigenere algorithm.

The result is a file `result.dat` containing the ciphered sequence.

# enigma

Generates the sequence off all combinations of five letters and ciphers with it with a 3 cylinders enigma machine.

The result is a file `result.dat` containing the ciphered sequence.

# testAESkey

Generates some tests on AES expansion key.

The result is a file `result.dat` containing the ciphered sequence.

# visCipher3d

Displays a sequence of ciphered data in a three dimensional world.

# visCipherCmp3d

Takes two sequences of ciphered data and compares their potentials links in a three dimensional world.
