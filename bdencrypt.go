package main
/* bdencrypt.go
PROGRAM: GoBD
AUTHOR: Ramzi Chennafi
DATE: October 18 2015
FUNCTIONS:
 intiateTools()
 encrypt_data(data string) []byte
 decrypt_data(data []byte) string

ABOUT:
  bdencrypt.go holds the functions responsible for AES-256 encryption within the GoBD program.
*/
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)
var iv []byte;
var block cipher.Block;
/* 
    FUNCTION: func intiateTools()
    RETURNS: Nothing

    ABOUT:
    Intiates the the iv and the cipher block for encryption and decryption.
*/
func intiateTools(){

	keytext := (([]byte)("s92jmc912hfye>p[c620cmi:pqinuysh"));
	block, _ = aes.NewCipher(keytext);
	ciphercode, _ := hex.DecodeString("a09c2cb3d389f6901176cbbd5ba9535f87f4f1532325bc9ecf336bb209073e7725f0a21255ab4cdf97a3a74ad0286b6d637145476af6dd740bad9214912f79de66190aef6e7a6789f46be6bf654286bf17c53a1d8c399ccdd4c59ac1c1df108709cc7690");
	iv = ciphercode[:aes.BlockSize];
}
/* 
    FUNCTION: func encrypt_data(data string) []byte
    RETURNS: []byte, the encrypted data
    ARGUMENTS: 
                string data - the data to encrypt

    ABOUT:
    Encrypts data using the programs specified algorithm. Returns the encrypted data.
*/
func encrypt_data(data string) []byte {
	
	text := ([]byte(data));
	
	cfb := cipher.NewCFBEncrypter(block, iv);
	ciphertext := make([]byte, len(text));
	cfb.XORKeyStream(ciphertext, text);

	return ciphertext;
}
/* 
    FUNCTION: func decrypt_data(data []byte) string
    RETURNS: String, the decrypted data
    ARGUMENTS: 
                []byte data - the encrypted data to decrypt

    ABOUT:
    Decrypts data using the programs specified algorithm. Returns the decrypted data.
*/
func decrypt_data(data []byte) string {
	
	cfbdec := cipher.NewCFBDecrypter(block, iv);
	plaintextCopy := make([]byte, len(data));
	cfbdec.XORKeyStream(plaintextCopy, data);

	return string(plaintextCopy[:]);
}
