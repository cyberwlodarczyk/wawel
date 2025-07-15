#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>
#include <errno.h>

#define eprintf(msg, ...) fprintf(stderr, (msg), ##__VA_ARGS__)

void *mem_alloc(size_t n)
{
    void *buf = malloc(n);
    if (buf == NULL)
    {
        eprintf("Error allocating memory\n");
        return NULL;
    }
    return buf;
}

void *mem_alloc_lock(size_t n)
{
    void *buf = mem_alloc(n);
    if (buf == NULL)
    {
        return NULL;
    }
    if (sodium_mlock(buf, n) == -1)
    {
        eprintf("Error locking memory\n");
        free(buf);
        return NULL;
    }
    return buf;
}

void mem_free(uint8_t *buf)
{
    free(buf);
}

bool mem_unlock_free(uint8_t *buf, size_t n)
{
    if (sodium_munlock(buf, n) == -1)
    {
        eprintf("Error unlocking memory\n");
        return false;
    }
    mem_free(buf);
    return true;
}

FILE *file_open(char *filename, char *mode)
{
    FILE *file = fopen(filename, mode);
    if (file == NULL)
    {
        eprintf("Error opening file \"%s\": %s\n", filename, strerror(errno));
    }
    return file;
}

size_t file_read(uint8_t *buf, size_t n, FILE *file)
{
    size_t k = fread(buf, 1, n, file);
    if (ferror(file))
    {
        eprintf("Error reading from file: %s\n", strerror(errno));
    }
    return k;
}

bool file_read_all(uint8_t *buf, size_t n, FILE *file)
{
    if (file_read(buf, n, file) != n)
    {
        if (feof(file))
        {
            eprintf("Error reading from file: unexpected eof\n");
        }
        return false;
    }
    return true;
}

bool file_write_all(uint8_t *buf, size_t n, FILE *file)
{
    if (fwrite(buf, 1, n, file) != n)
    {
        eprintf("Error writing to file: %s\n", strerror(errno));
        return false;
    }
    return true;
}

bool file_remove(char *filename)
{
    if (remove(filename) == -1)
    {
        eprintf("Error removing file \"%s\": %s\n", filename, strerror(errno));
        return false;
    }
    return true;
}

const char EXT_STR[] = ".wawel";

#define EXT_SIZE (sizeof(EXT_STR) - 1)

bool ext_check(char *filename, size_t size)
{
    return size > EXT_SIZE && strcmp(filename + size - EXT_SIZE, EXT_STR) == 0;
}

char *ext_add(char *filename, size_t size)
{
    char *result = mem_alloc(size + EXT_SIZE + 1);
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
    char *result = mem_alloc(n + 1);
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
    if (!file_write_all(header, aead_HEADER_SIZE, dst))
    {
        return false;
    }
    uint8_t input[aead_CHUNK_SIZE];
    uint8_t output[aead_CHUNK_SIZE + aead_EXTRA_SIZE];
    while (true)
    {
        size_t n = file_read(input, aead_CHUNK_SIZE, src);
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
        if (!file_write_all(output, n + aead_EXTRA_SIZE, dst))
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
    if (!file_read_all(header, aead_HEADER_SIZE, src))
    {
        return false;
    }
    aead_state state;
    if (aead_init_pull(&state, header, key) != 0)
    {
        eprintf("File is corrupted\n");
        return false;
    }
    uint8_t input[aead_CHUNK_SIZE + aead_EXTRA_SIZE];
    uint8_t output[aead_CHUNK_SIZE];
    uint8_t tag;
    while (true)
    {
        size_t n = file_read(input, aead_CHUNK_SIZE + aead_EXTRA_SIZE, src);
        if (ferror(src))
        {
            return false;
        }
        int eof = feof(src);
        if (aead_pull(&state, output, NULL, &tag, input, n, NULL, 0) != 0)
        {
            eprintf("Password is invalid or file is corrupted\n");
            return false;
        }
        if ((!eof && tag != 0) || (eof && tag != aead_TAG_FINAL))
        {
            eprintf("File is corrupted\n");
            return false;
        }
        if (!file_write_all(output, n - aead_EXTRA_SIZE, dst))
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

uint8_t *kdf_derive_key(
    uint8_t *password,
    size_t password_len,
    uint8_t salt[kdf_SALT_SIZE])
{
    uint8_t *key = mem_alloc_lock(aead_KEY_SIZE);
    if (key == NULL)
    {
        return NULL;
    }
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
        eprintf("Error deriving secret key\n");
        mem_unlock_free(key, aead_KEY_SIZE);
        return NULL;
    }
    return key;
}

void kdf_gen_salt(uint8_t salt[kdf_SALT_SIZE])
{
    randombytes_buf(salt, kdf_SALT_SIZE);
}

#define PASSWORD_MIN_LENGTH 12
#define PASSWORD_MAX_LENGTH 64

bool password_set_echo(bool is_echo)
{
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) == -1)
    {
        eprintf("Error getting terminal settings\n");
        return false;
    }
    if (is_echo)
    {
        term.c_lflag |= ECHO | ICANON;
    }
    else
    {
        term.c_lflag &= ~(ECHO | ICANON);
    }
    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
    {
        eprintf("Error setting terminal settings\n");
        return false;
    }
    return true;
}

size_t password_get(uint8_t *buf)
{
    int c;
    size_t n = 0;
    printf("Password: ");
    if (!password_set_echo(false))
    {
        return -1;
    }
    while (true)
    {
        c = getchar();
        if (ferror(stdin))
        {
            eprintf("Error reading from stdin: %s\n", strerror(errno));
            password_set_echo(true);
            return -1;
        }
        if (feof(stdin) || c == '\n')
        {
            if (n < PASSWORD_MIN_LENGTH)
            {
                eprintf(
                    "\nPassword must be at least %d characters long\n",
                    PASSWORD_MIN_LENGTH);
                password_set_echo(true);
                return -1;
            }
            else
            {
                putchar('\n');
                break;
            }
        }
        if ((c == '\b' || c == 127) && n > 0)
        {
            n--;
            printf("\b \b");
        }
        else if (n < PASSWORD_MAX_LENGTH)
        {
            buf[n++] = c;
            putchar('*');
        }
        else
        {
            eprintf(
                "\nPassword must be at most %d characters long\n",
                PASSWORD_MAX_LENGTH);
            password_set_echo(true);
            return -1;
        }
    }
    if (!password_set_echo(true))
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
    kdf_gen_salt(salt);
    if (!file_write_all(salt, kdf_SALT_SIZE, dst))
    {
        return false;
    }
    uint8_t *key = kdf_derive_key(password, password_len, salt);
    if (key == NULL)
    {
        return false;
    }
    bool ok = aead_encrypt(src, dst, key);
    return mem_unlock_free(key, aead_KEY_SIZE) && ok;
}

bool wawel_decrypt(
    FILE *src,
    FILE *dst,
    uint8_t *password,
    size_t password_len)
{
    uint8_t salt[kdf_SALT_SIZE];
    if (!file_read_all(salt, kdf_SALT_SIZE, src))
    {
        return false;
    }
    uint8_t *key = kdf_derive_key(password, password_len, salt);
    if (key == NULL)
    {
        return false;
    }
    bool ok = aead_decrypt(src, dst, key);
    return mem_unlock_free(key, aead_KEY_SIZE) && ok;
}

bool wawel_run(int argc, char **argv)
{
    if (sodium_init() == -1)
    {
        eprintf("Error initalizing sodium\n");
        return false;
    }
    if (argc != 2)
    {
        eprintf("Usage: %s <file>\n", argv[0]);
        return false;
    }
    char *src_filename = argv[1];
    size_t src_filename_len = strlen(src_filename);
    FILE *src = file_open(src_filename, "rb");
    if (src == NULL)
    {
        return false;
    }
    uint8_t *password = mem_alloc_lock(PASSWORD_MAX_LENGTH);
    if (password == NULL)
    {
        return false;
    }
    size_t password_len = password_get(password);
    if (password_len == -1)
    {
        mem_unlock_free(password, PASSWORD_MAX_LENGTH);
        return false;
    }
    bool is_encrypted = ext_check(src_filename, src_filename_len);
    char *(*ext_fn)(char *, size_t) = is_encrypted ? ext_remove : ext_add;
    char *dst_filename = ext_fn(src_filename, src_filename_len);
    if (dst_filename == NULL)
    {
        mem_unlock_free(password, PASSWORD_MAX_LENGTH);
        return false;
    }
    FILE *dst = file_open(dst_filename, "wb");
    if (dst == NULL)
    {
        mem_unlock_free(password, PASSWORD_MAX_LENGTH);
        mem_free(dst_filename);
        return false;
    }
    bool (*fn)(FILE *, FILE *, uint8_t *, size_t) =
        is_encrypted ? wawel_decrypt : wawel_encrypt;
    bool ok = fn(src, dst, password, password_len);
    if (ok)
    {
        printf("Successfully created \"%s\"\n", dst_filename);
    }
    else
    {
        file_remove(dst_filename);
    }
    mem_free(dst_filename);
    return mem_unlock_free(password, PASSWORD_MAX_LENGTH) && ok;
}

int main(int argc, char **argv)
{
    return wawel_run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE;
}
