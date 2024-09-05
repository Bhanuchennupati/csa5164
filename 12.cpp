#include <stdio.h>
#include <stdint.h>
uint8_t sdes_encrypt(uint8_t input, uint8_t k1, uint8_t k2);
uint8_t sdes_decrypt(uint8_t input, uint8_t k1, uint8_t k2);
uint8_t xor_8bit(uint8_t a, uint8_t b);
void cbc_encrypt(uint8_t *plain, uint8_t *cipher, uint8_t iv, uint8_t k1, uint8_t k2, int size) {
    uint8_t prev = iv;
    for (int i = 0; i < size; i++) {
        cipher[i] = sdes_encrypt(xor_8bit(plain[i], prev), k1, k2);
        prev = cipher[i];
    }
}
void cbc_decrypt(uint8_t *cipher, uint8_t *plain, uint8_t iv, uint8_t k1, uint8_t k2, int size) {
    uint8_t prev = iv;
    for (int i = 0; i < size; i++) {
        plain[i] = xor_8bit(sdes_decrypt(cipher[i], k1, k2), prev);
        prev = cipher[i];
    }
}
uint8_t sdes_encrypt(uint8_t input, uint8_t k1, uint8_t k2) {
    return input ^ k1; 
}
uint8_t sdes_decrypt(uint8_t input, uint8_t k1, uint8_t k2) {
    return input ^ k1; 
}
uint8_t xor_8bit(uint8_t a, uint8_t b) {
    return a ^ b;
}
int main() {
    uint8_t plaintext[] = {0x01, 0x23}; 
    uint8_t ciphertext[2];
    uint8_t decryptedtext[2];
    uint8_t iv = 0xAA; 
    uint8_t k1 = 0x2D, k2 = 0x3F; 
    cbc_encrypt(plaintext, ciphertext, iv, k1, k2, 2);
    printf("Encrypted: %02X %02X\n", ciphertext[0], ciphertext[1]);
    cbc_decrypt(ciphertext, decryptedtext, iv, k1, k2, 2);
    printf("Decrypted: %02X %02X\n", decryptedtext[0], decryptedtext[1]);
    return 0;
}