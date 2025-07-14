#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

#define eprintf(msg, ...) fprintf(stderr, (msg), ##__VA_ARGS__)

void *alloc(size_t size)
{
    void *buf = malloc(size);
    if (buf == NULL)
    {
        eprintf("Error allocating memory\n");
        return NULL;
    }
    return buf;
}

const char EXT_STR[] = ".wawel";

#define EXT_SIZE (sizeof(EXT_STR) - 1)

bool ext_check(char *filename, size_t size)
{
    return size > EXT_SIZE && strcmp(filename + size - EXT_SIZE, EXT_STR) == 0;
}

char *ext_add(char *filename, size_t size)
{
    char *result = alloc(size + EXT_SIZE + 1);
    if (result == NULL)
    {
        return NULL;
    }
    strncpy(result, filename, size);
    strcpy(result + size, EXT_STR);
    return result;
}

char *ext_remove(char *filename, size_t size)
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

#define aead_state crypto_secretstream_xchacha20poly1305_state
#define aead_init_push crypto_secretstream_xchacha20poly1305_init_push
#define aead_push crypto_secretstream_xchacha20poly1305_push
#define aead_init_pull crypto_secretstream_xchacha20poly1305_init_pull
#define aead_pull crypto_secretstream_xchacha20poly1305_pull
#define aead_TAG_FINAL crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define aead_EXTRA_SIZE crypto_secretstream_xchacha20poly1305_ABYTES
#define aead_KEY_SIZE crypto_secretstream_xchacha20poly1305_KEYBYTES
#define aead_HEADER_SIZE crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define aead_CHUNK_SIZE 4096

bool aead_encrypt(FILE *src, FILE *dst, uint8_t *key)
{
    uint8_t header[aead_HEADER_SIZE];
    aead_state state;
    aead_init_push(&state, header, key);
    if (fwrite(header, 1, aead_HEADER_SIZE, dst) != aead_HEADER_SIZE)
    {
        return false;
    }
    uint8_t input[aead_CHUNK_SIZE];
    uint8_t output[aead_CHUNK_SIZE + aead_EXTRA_SIZE];
    while (true)
    {
        size_t n = fread(input, 1, aead_CHUNK_SIZE, src);
        if (ferror(src))
        {
            return false;
        }
        int eof = feof(src);
        aead_push(
            &state,
            output,
            NULL,
            input,
            n,
            NULL,
            0,
            eof ? aead_TAG_FINAL : 0);
        if (fwrite(output, 1, n + aead_EXTRA_SIZE, dst) != n + aead_EXTRA_SIZE)
        {
            return false;
        }
        if (eof)
        {
            return true;
        }
    }
}

bool aead_decrypt(FILE *src, FILE *dst, uint8_t *key)
{
    uint8_t header[aead_HEADER_SIZE];
    if (fread(header, 1, aead_HEADER_SIZE, src) != aead_HEADER_SIZE)
    {
        return false;
    }
    aead_state state;
    if (aead_init_pull(&state, header, key) != 0)
    {
        return false;
    }
    uint8_t input[aead_CHUNK_SIZE + aead_EXTRA_SIZE];
    uint8_t output[aead_CHUNK_SIZE];
    uint8_t tag;
    while (true)
    {
        size_t n = fread(input, 1, aead_CHUNK_SIZE + aead_EXTRA_SIZE, src);
        if (ferror(src))
        {
            return false;
        }
        int eof = feof(src);
        if (aead_pull(&state, output, NULL, &tag, input, n, NULL, 0) != 0)
        {
            return false;
        }
        if ((!eof && tag != 0) || (eof && tag != aead_TAG_FINAL))
        {
            return false;
        }
        if (fwrite(output, 1, n - aead_EXTRA_SIZE, dst) != n - aead_EXTRA_SIZE)
        {
            return false;
        }
        if (eof)
        {
            return true;
        }
    }
}

#define kdf_SALT_SIZE crypto_pwhash_SALTBYTES

bool kdf_derive(
    uint8_t *password,
    size_t password_len,
    uint8_t salt[kdf_SALT_SIZE],
    uint8_t key[aead_KEY_SIZE])
{
    if (crypto_pwhash(
            key,
            aead_KEY_SIZE,
            password,
            password_len,
            salt,
            crypto_pwhash_OPSLIMIT_SENSITIVE,
            crypto_pwhash_MEMLIMIT_SENSITIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false;
    }
    return true;
}

bool terminal_edit_settings(void (*f)(struct termios *))
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

void terminal_disable_echo(struct termios *term)
{
    term->c_lflag &= ~(ECHO | ICANON);
}

void terminal_enable_echo(struct termios *term)
{
    term->c_lflag |= ECHO | ICANON;
}

#define PASSWORD_MAX_LENGTH 64

size_t password_get(uint8_t *buf)
{
    uint8_t c;
    size_t n = 0;
    printf("Password: ");
    if (!terminal_edit_settings(terminal_disable_echo))
    {
        return -1;
    }
    while (true)
    {
        c = getchar();
        if (c == '\n')
        {
            putchar('\n');
            break;
        }
        if (c == '\b' && n > 0)
        {
            n--;
        }
        else if (n < PASSWORD_MAX_LENGTH)
        {
            buf[n++] = c;
            putchar('*');
        }
        else
        {
            eprintf("\nPassword is too long\n");
            return -1;
        }
    }
    if (!terminal_edit_settings(terminal_enable_echo))
    {
        return -1;
    }
    return n;
}

bool wawel_encrypt(
    FILE *src,
    FILE *dst,
    uint8_t *password,
    size_t password_len)
{
    uint8_t salt[kdf_SALT_SIZE];
    randombytes_buf(salt, kdf_SALT_SIZE);
    if (fwrite(salt, 1, kdf_SALT_SIZE, dst) != kdf_SALT_SIZE)
    {
        return false;
    }
    uint8_t key[aead_KEY_SIZE];
    return kdf_derive(password, password_len, salt, key) &&
           aead_encrypt(src, dst, key);
}

bool wawel_decrypt(
    FILE *src,
    FILE *dst,
    uint8_t *password,
    size_t password_len)
{
    uint8_t salt[kdf_SALT_SIZE];
    if (fread(salt, 1, kdf_SALT_SIZE, src) != kdf_SALT_SIZE)
    {
        return false;
    }
    uint8_t key[aead_KEY_SIZE];
    return kdf_derive(password, password_len, salt, key) &&
           aead_decrypt(src, dst, key);
}

bool wawel_run(int argc, char **argv)
{
    if (sodium_init() == -1)
    {
        return false;
    }
    if (argc != 2)
    {
        return false;
    }
    char *src_filename = argv[1];
    size_t src_filename_len = strlen(src_filename);
    FILE *src = fopen(src_filename, "rb");
    if (src == NULL)
    {
        return false;
    }
    uint8_t *password = alloc(PASSWORD_MAX_LENGTH);
    size_t password_len = password_get(password);
    if (password_len == -1)
    {
        return false;
    }
    bool is_encrypted = ext_check(src_filename, src_filename_len);
    char *(*ext_fn)(char *, size_t) = is_encrypted ? ext_remove : ext_add;
    char *dst_filename = ext_fn(src_filename, src_filename_len);
    if (dst_filename == NULL)
    {
        return false;
    }
    FILE *dst = fopen(dst_filename, "wb");
    if (dst == NULL)
    {
        return false;
    }
    bool (*fn)(FILE *, FILE *, uint8_t *, size_t) =
        is_encrypted ? wawel_decrypt : wawel_encrypt;
    return fn(src, dst, password, password_len);
}

int main(int argc, char **argv)
{
    return wawel_run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
