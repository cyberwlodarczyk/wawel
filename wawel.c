#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sodium.h>

#define TAG_SIZE crypto_aead_chacha20poly1305_ABYTES
#define KEY_SIZE crypto_aead_chacha20poly1305_KEYBYTES
#define NONCE_SIZE crypto_aead_chacha20poly1305_NPUBBYTES
#define EXT_SIZE (sizeof(EXT) - 1)

const char EXT[] = ".wawel";

char *add_ext(char *filename)
{
    size_t n = strlen(filename);
    char *result = malloc(n + EXT_SIZE + 1);
    strncpy(result, filename, n);
    strcpy(result + n, EXT);
    return result;
}

char *remove_ext(char *filename)
{
    size_t n = strlen(filename), m = n - EXT_SIZE;
    if (n < EXT_SIZE + 1 || strcmp(filename + m, EXT) != 0)
    {
        return NULL;
    }
    char *result = malloc(m + 1);
    strncpy(result, filename, m);
    result[m] = '\0';
    return result;
}

bool decode_key(char *hex, uint8_t key[KEY_SIZE])
{
    if (strlen(hex) != KEY_SIZE * 2)
    {
        return false;
    }
    for (size_t i = 0; i < KEY_SIZE * 2; i++)
    {
        uint8_t x;
        if (hex[i] >= '0' && hex[i] <= '9')
        {
            x = hex[i] - '0';
        }
        else if (hex[i] >= 'A' && hex[i] <= 'F')
        {
            x = hex[i] - 'A' + 10;
        }
        else if (hex[i] >= 'a' && hex[i] <= 'f')
        {
            x = hex[i] - 'a' + 10;
        }
        else
        {
            return false;
        }
        if (i % 2 == 0)
        {
            key[i / 2] = x << 4;
        }
        else
        {
            key[i / 2] |= x;
        }
    }
    return true;
}

int encrypt(uint8_t *ciphertext,
            size_t *ciphertext_size,
            uint8_t *plaintext,
            size_t plaintext_size,
            uint8_t *nonce,
            uint8_t key[KEY_SIZE])
{
    return crypto_aead_chacha20poly1305_encrypt(ciphertext,
                                                (unsigned long long *)ciphertext_size,
                                                plaintext,
                                                plaintext_size,
                                                NULL,
                                                0,
                                                NULL,
                                                nonce,
                                                key);
}

int decrypt(uint8_t *plaintext,
            size_t *plaintext_size,
            uint8_t *ciphertext,
            size_t ciphertext_size,
            uint8_t *nonce,
            uint8_t key[KEY_SIZE])
{
    return crypto_aead_chacha20poly1305_decrypt(plaintext,
                                                (unsigned long long *)plaintext_size,
                                                NULL,
                                                ciphertext,
                                                ciphertext_size,
                                                NULL,
                                                0,
                                                nonce,
                                                key);
}

int main(int argc, char **argv)
{
    if (sodium_init() == -1)
    {
        fprintf(stderr, "Error initalizing libsodium\n");
        return EXIT_FAILURE;
    }
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <file> <key>\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint8_t key[KEY_SIZE];
    if (!decode_key(argv[2], key))
    {
        fprintf(stderr, "Error decoding the key\n");
        return EXIT_FAILURE;
    }
    FILE *file;
    file = fopen(argv[1], "rb");
    if (file == NULL)
    {
        perror("Error opening the source file");
        return EXIT_FAILURE;
    }
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "Error determining the size of the source file\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    size_t n = ftell(file), m;
    if (n == -1)
    {
        fprintf(stderr, "Error determining the size of the source file\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "Error determining the size of the source file\n");
        fclose(file);
        return EXIT_FAILURE;
    }
    uint8_t *input = malloc(n), *output;
    if (fread(input, 1, n, file) != n || ferror(file))
    {
        perror("Error reading from the source file");
        fclose(file);
        free(input);
        return EXIT_FAILURE;
    }
    fclose(file);
    char *filename = remove_ext(argv[1]);
    if (filename == NULL)
    {
        filename = add_ext(argv[1]);
        output = malloc(n + NONCE_SIZE + TAG_SIZE);
        randombytes_buf(output, NONCE_SIZE);
        encrypt(output + NONCE_SIZE, &m, input, n, output, key);
        m += NONCE_SIZE;
    }
    else
    {
        output = malloc(n - NONCE_SIZE - TAG_SIZE);
        if (decrypt(output, &m, input + NONCE_SIZE, n - NONCE_SIZE, input, key) != 0)
        {
            fprintf(stderr, "Error decrypting the destination file: Message forged\n");
            free(filename);
            free(input);
            free(output);
            return EXIT_FAILURE;
        }
    }
    file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Error opening the destination file");
        free(filename);
        free(input);
        free(output);
        return EXIT_FAILURE;
    }
    if (fwrite(output, 1, m, file) != m || ferror(file))
    {
        perror("Error writing to the destination file");
        fclose(file);
        free(filename);
        free(input);
        free(output);
        return EXIT_FAILURE;
    }
    fclose(file);
    free(filename);
    free(input);
    free(output);
    return EXIT_SUCCESS;
}
