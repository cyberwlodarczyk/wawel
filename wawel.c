#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

#define eprintf(msg, ...) fprintf(stderr, (msg), ##__VA_ARGS__)
#define SALT_SIZE crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#define KEY_SIZE crypto_aead_chacha20poly1305_KEYBYTES
#define NONCE_SIZE crypto_aead_chacha20poly1305_NPUBBYTES
#define TAG_SIZE crypto_aead_chacha20poly1305_ABYTES
#define ADDITIONAL_SIZE (SALT_SIZE + NONCE_SIZE + TAG_SIZE)
#define PASSWORD_BUFFER_SIZE 64
#define EXT_SIZE (sizeof(EXT) - 1)

const char EXT[] = ".wawel";

void *alloc(size_t size)
{
    void *buffer = malloc(size);
    if (buffer == NULL)
    {
        eprintf("Error allocating memory\n");
        return NULL;
    }
    return buffer;
}

bool is_ext(char *filename, size_t size)
{
    return size > EXT_SIZE && strcmp(filename + size - EXT_SIZE, EXT) == 0;
}

char *add_ext(char *filename, size_t size)
{
    char *result = alloc(size + EXT_SIZE + 1);
    if (result == NULL)
    {
        return NULL;
    }
    strncpy(result, filename, size);
    strcpy(result + size, EXT);
    return result;
}

char *remove_ext(char *filename, size_t size)
{
    size_t n = size - EXT_SIZE;
    char *result = alloc(n + 1);
    if (result == NULL)
    {
        return NULL;
    }
    strncpy(result, filename, n);
    result[n] = '\0';
    return result;
}

bool derive_key(char *password, uint8_t *salt, uint8_t key[KEY_SIZE])
{
    if (crypto_pwhash_scryptsalsa208sha256(
            key,
            KEY_SIZE,
            password,
            strlen(password),
            salt,
            crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
    {
        eprintf("Error deriving a key from the password\n");
        return false;
    }
    return true;
}

int encrypt(
    uint8_t *ciphertext,
    size_t *ciphertext_size,
    uint8_t *plaintext,
    size_t plaintext_size,
    uint8_t *nonce,
    uint8_t key[KEY_SIZE])
{
    return crypto_aead_chacha20poly1305_encrypt(
        ciphertext,
        (unsigned long long *)ciphertext_size,
        plaintext,
        plaintext_size,
        NULL,
        0,
        NULL,
        nonce,
        key);
}

int decrypt(
    uint8_t *plaintext,
    size_t *plaintext_size,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    uint8_t *nonce,
    uint8_t key[KEY_SIZE])
{
    return crypto_aead_chacha20poly1305_decrypt(
        plaintext,
        (unsigned long long *)plaintext_size,
        NULL,
        ciphertext,
        ciphertext_size,
        NULL,
        0,
        nonce,
        key);
}

bool get_file_size(FILE *file, size_t *size)
{
    if (fseek(file, 0, SEEK_END) != 0)
    {
        eprintf("Error determining the size of the source file\n");
        return false;
    }
    size_t n = ftell(file);
    if (n == -1 || fseek(file, 0, SEEK_SET) != 0)
    {
        eprintf("Error determining the size of the source file\n");
        return false;
    }
    if (n > 1 << 29)
    {
        eprintf("The size of the source file cannot exceed 512MB\n");
        return false;
    }
    *size = n;
    return true;
}

bool read_file(char *filename, uint8_t **content, size_t *size)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Error opening the source file");
        return false;
    }
    size_t n;
    if (!get_file_size(file, &n))
    {
        fclose(file);
        return false;
    }
    uint8_t *buffer = alloc(n);
    if (buffer == NULL)
    {
        fclose(file);
        return false;
    }
    if (fread(buffer, 1, n, file) != n || ferror(file))
    {
        perror("Error reading from the source file");
        fclose(file);
        free(buffer);
        return false;
    }
    fclose(file);
    *content = buffer;
    *size = n;
    return true;
}

bool write_file(char *filename, uint8_t *content, size_t size)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Error opening the destination file");
        return false;
    }
    if (fwrite(content, 1, size, file) != size || ferror(file))
    {
        perror("Error writing to the destination file");
        fclose(file);
        return false;
    }
    fclose(file);
    return true;
}

bool edit_terminal_settings(void (*f)(struct termios *))
{
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) == -1)
    {
        eprintf("Error getting terminal settings\n");
        return false;
    }
    f(&term);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
    {
        eprintf("Error setting terminal settings\n");
        return false;
    }
    return true;
}

void disable_echo_and_canonical_input(struct termios *term)
{
    term->c_lflag &= ~(ECHO | ICANON);
}

void enable_echo_and_canonical_input(struct termios *term)
{
    term->c_lflag |= ECHO | ICANON;
}

bool get_password(char **result)
{
    char c, buffer[PASSWORD_BUFFER_SIZE];
    size_t n = 0;
    printf("Password: ");
    if (!edit_terminal_settings(disable_echo_and_canonical_input))
    {
        return false;
    }
    while (true)
    {
        c = getchar();
        if (c == '\n')
        {
            buffer[n++] = '\0';
            putchar('\n');
            break;
        }
        if (c == '\b' && n > 0)
        {
            n--;
        }
        else if (n < PASSWORD_BUFFER_SIZE)
        {
            buffer[n++] = c;
            putchar('*');
        }
        else
        {
            eprintf("\nPassword is too large\n");
            return false;
        }
    }
    if (!edit_terminal_settings(enable_echo_and_canonical_input))
    {
        return false;
    }
    *result = alloc(n);
    if (*result == NULL)
    {
        return false;
    }
    memcpy(*result, buffer, n);
    return true;
}

int main(int argc, char **argv)
{
    if (sodium_init() == -1)
    {
        eprintf("Error initalizing libsodium\n");
        return EXIT_FAILURE;
    }
    if (argc != 2)
    {
        eprintf("Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *filename = argv[1], *password;
    if (!get_password(&password))
    {
        return EXIT_FAILURE;
    }
    uint8_t *input, *output;
    size_t input_size, output_size, filename_size = strlen(filename);
    if (!read_file(argv[1], &input, &input_size))
    {
        free(password);
        return EXIT_FAILURE;
    }
    if (is_ext(filename, filename_size))
    {
        filename = remove_ext(filename, filename_size);
        if (filename == NULL)
        {
            free(password);
            free(input);
            return EXIT_FAILURE;
        }
        if (input_size < ADDITIONAL_SIZE)
        {
            eprintf("The encrypted message is forged\n");
            free(filename);
            free(password);
            free(input);
            return EXIT_FAILURE;
        }
        uint8_t key[KEY_SIZE];
        if (!derive_key(password, input, key))
        {
            free(filename);
            free(password);
            free(input);
            return EXIT_FAILURE;
        }
        free(password);
        output = alloc(input_size - ADDITIONAL_SIZE);
        if (output == NULL)
        {
            free(filename);
            free(input);
            return EXIT_FAILURE;
        }
        if (decrypt(
                output,
                &output_size,
                input + SALT_SIZE + NONCE_SIZE,
                input_size - SALT_SIZE - NONCE_SIZE,
                input + SALT_SIZE,
                key) != 0)
        {
            eprintf("The encrypted message is forged or the password is invalid\n");
            free(filename);
            free(input);
            free(output);
            return EXIT_FAILURE;
        }
    }
    else
    {
        filename = add_ext(filename, filename_size);
        if (filename == NULL)
        {
            free(password);
            free(input);
            return EXIT_FAILURE;
        }
        output = alloc(input_size + ADDITIONAL_SIZE);
        if (output == NULL)
        {
            free(filename);
            free(password);
            free(input);
            return EXIT_FAILURE;
        }
        randombytes_buf(output, SALT_SIZE);
        randombytes_buf(output + SALT_SIZE, NONCE_SIZE);
        uint8_t key[KEY_SIZE];
        if (!derive_key(password, output, key))
        {
            free(filename);
            free(password);
            free(input);
            free(output);
            return EXIT_FAILURE;
        }
        free(password);
        encrypt(output + SALT_SIZE + NONCE_SIZE, &output_size, input, input_size, output + SALT_SIZE, key);
        output_size += SALT_SIZE + NONCE_SIZE;
    }
    free(input);
    if (!write_file(filename, output, output_size))
    {
        free(filename);
        free(output);
        return EXIT_FAILURE;
    }
    free(filename);
    free(output);
    return EXIT_SUCCESS;
}
