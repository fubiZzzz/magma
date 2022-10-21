#include <stdio.h>
#include <stdint.h>
#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((uint64_t)1 << N) - 1))
#define BUFF_SIZE 1024

size_t GOST(uint8_t * to, uint8_t mode, uint8_t * key256b, uint8_t * from, size_t length);
void feistel_cipher(uint8_t mode, uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b);
void round_of_feistel_cipher(uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b, uint8_t round);

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row);
void substitution_table_by_4bits(uint8_t * blocks4b, uint8_t sbox_row);

void s256to32(uint8_t * key256b, uint32_t * keys32b);
void s64to32(uint64_t block64b, uint32_t * block32b_1, uint32_t * block32b_2);
void s64to8(uint64_t block64b, uint8_t * blocks8b);
void s32to8(uint32_t block32b, uint8_t * blocks4b);

uint64_t j32to64(uint32_t block32b_1, uint32_t block32b_2);
uint64_t j8to64(uint8_t * blocks8b);
uint32_t j4to32(uint8_t * blocks4b);

static inline void print_array(uint8_t * array, size_t length);
static inline void print_bits(uint64_t x, register uint64_t Nbit);

// 1 | 4 -> 0xC
static const uint8_t Sbox[8][16] = {
    {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3},
    {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
    {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
    {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
    {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
    {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
    {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
    {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
};

int main(void) {
    uint8_t encrypted[BUFF_SIZE], decrypted[BUFF_SIZE];
    uint8_t key256b[32] = "I_LOVE_RTU_MIREA_From_KKSO_KEK_W";
    uint8_t buffer[BUFF_SIZE], ch;
    size_t position;
    while ((ch = getchar()) != '\n' && position < BUFF_SIZE - 1)
        buffer[position++] = ch;
    buffer[position] = '\0';

    printf("Open message:\n");
    printf("%s\n", buffer);
    putchar('\n');

    position = GOST(encrypted, 'E', key256b, buffer, position);
    printf("Encrypted message:\n");
    printf("%s\n", encrypted);
    putchar('\n');

    printf("Decrypted message:\n");
    position = GOST(decrypted, 'D', key256b, encrypted, position);
    printf("%s\n", decrypted);
    putchar('\n');

    return 0;
}

size_t GOST(uint8_t * to, uint8_t mode, uint8_t * key256b, uint8_t * from, size_t length) {
    length = length % 8 == 0 ? length : length + (8 - (length % 8));
    uint32_t N1, N2, keys32b[8];
    s256to32(key256b, keys32b);

    for (size_t i = 0; i < length; i += 8) {
        s64to32(
            j8to64(from + i),
            &N1, &N2
        );
        feistel_cipher(mode, &N1, &N2, keys32b);
        s64to8(
            j32to64(N1, N2),
            (to + i)
        );
    }

    return length;
}

// keys32b = [K0, K1, K2, K3, K4, K5, K6, K7]
void feistel_cipher(uint8_t mode, uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b) {
    switch (mode) {
        case 'E': case 'e': {
            // K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7, K0, K1, K2, K3, K4, K5, K6, K7
            for (uint8_t round = 0; round < 24; ++round)
                round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);

            // K7, K6, K5, K4, K3, K2, K1, K0
            for (uint8_t round = 31; round >= 24; --round)
                round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);
            break;
        }
        case 'D': case 'd': {
            // K0, K1, K2, K3, K4, K5, K6, K7
            for (uint8_t round = 0; round < 8; ++round)
                round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);

            // K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0, K7, K6, K5, K4, K3, K2, K1, K0
            for (uint8_t round = 31; round >= 8; --round)
                round_of_feistel_cipher(block32b_1, block32b_2, keys32b, round);
            break;
        }
    }
}

void round_of_feistel_cipher(uint32_t * block32b_1, uint32_t * block32b_2, uint32_t * keys32b, uint8_t round) {
    uint32_t result_of_iter, temp;
    result_of_iter = (*block32b_1 + keys32b[round % 8]) % UINT32_MAX;
    result_of_iter = substitution_table(result_of_iter, round % 8);
    result_of_iter = (uint32_t)LSHIFT_nBIT(result_of_iter, 11, 32);
    temp = *block32b_1;
    *block32b_1 = result_of_iter ^ *block32b_2;
    *block32b_2 = temp;
}

uint32_t substitution_table(uint32_t block32b, uint8_t sbox_row) {
    uint8_t blocks4bits[4];
    s32to8(block32b, blocks4bits);
    substitution_table_by_4bits(blocks4bits, sbox_row);
    return j4to32(blocks4bits);
}

void substitution_table_by_4bits(uint8_t * blocks4b, uint8_t sbox_row) {
    uint8_t block4b_1, block4b_2;
    for (uint8_t i = 0; i < 4; ++i) {
        // 10101100 & 0x0F = 00001100
        // [example get from table] 1100 -> 1001

        block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];
        block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];
        blocks4b[i] = block4b_2;
        blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
    }
}

void s256to32(uint8_t * key256b, uint32_t * keys32b) {
    uint8_t *p8 = key256b;
    for (uint32_t *p32 = keys32b; p32 < keys32b + 8; ++p32) {
        // 00000000000000000000000000000000 << 8 | 10010010 = 00000000000000000000000010010010
        for (uint8_t i = 0; i < 4; ++i) {
            *p32 = (*p32 << 8) | *(p8 + i);
        }
        p8 += 4;
    }
}

void s64to32(uint64_t block64b, uint32_t * block32b_1, uint32_t * block32b_2) {
    *block32b_2 = (uint32_t)(block64b);
    *block32b_1 = (uint32_t)(block64b >> 32);
}

void s64to8(uint64_t block64b, uint8_t * blocks8b) {
    for (size_t i = 0; i < 8; ++i) {
        blocks8b[i] = (uint8_t)(block64b >> ((7 - i) * 8));
    }
}

void s32to8(uint32_t block32b, uint8_t * blocks8b) {
    for (uint8_t i = 0; i < 4; ++i) {
        blocks8b[i] = (uint8_t)(block32b >> (24 - (i * 8)));
    }
}

uint64_t j32to64(uint32_t block32b_1, uint32_t block32b_2) {
    uint64_t block64b;
    block64b = block32b_2;
    block64b = (block64b << 32) | block32b_1;
    return block64b;
}

uint64_t j8to64(uint8_t * blocks8b) {
    uint64_t block64b;
    for (uint8_t *p = blocks8b; p < blocks8b + 8; ++p) {
        // i = 0
        // (0000000000000000000000000000000000000000000000000000000000000000 << 8) | 11001100 =
        // 0000000000000000000000000000000000000000000000000000000011001100
        block64b = (block64b << 8) | *p;
    }
    return block64b;
}

uint32_t j4to32(uint8_t * blocks4b) {
    uint32_t block32b;
    for (uint8_t i = 0; i < 4; ++i) {
        block32b = (block32b << 8) | blocks4b[i];
    }
    return block32b;
}

static inline void print_array(uint8_t * array, size_t length) {
    printf("[ ");
    for (size_t i = 0; i < length; ++i)
        printf("%d ", array[i]);
    printf("]\n");
}

static inline void print_bits(uint64_t x, register uint64_t Nbit) {
    for (Nbit = (uint64_t)1 << (Nbit - 1); Nbit > 0x00; Nbit >>= 1)
        printf("%d", (x & Nbit) ? 1 : 0);
    putchar('\n');
}
