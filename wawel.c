#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define BUFFER_SIZE 1024
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

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file>", argv[0]);
        return EXIT_FAILURE;
    }
    FILE *src, *dest;
    char *filename = remove_ext(argv[1]);
    bool decryption = true;
    if (filename == NULL)
    {
        decryption = false;
        filename = add_ext(argv[1]);
    }
    src = fopen(argv[1], "rb");
    if (src == NULL)
    {
        perror("Error opening source file");
        return EXIT_FAILURE;
    }
    dest = fopen(filename, "wb");
    if (dest == NULL)
    {
        perror("Error opening destination file");
        fclose(src);
        return EXIT_FAILURE;
    }
    uint8_t buffer[BUFFER_SIZE];
    size_t n;
    while ((n = fread(buffer, 1, BUFFER_SIZE, src)) > 0)
    {
        for (size_t i = 0; i < n; i++)
        {
            if (decryption)
            {
                buffer[i] -= 1;
            }
            else
            {
                buffer[i] += 1;
            }
        }
        fwrite(buffer, 1, n, dest);
    }
    if (ferror(src))
    {
        perror("Error reading from source file");
        fclose(src);
        fclose(dest);
        return EXIT_FAILURE;
    }
    if (ferror(dest))
    {
        perror("Error writing to destination file");
        fclose(src);
        fclose(dest);
        return EXIT_FAILURE;
    }
    fclose(src);
    fclose(dest);
    free(filename);
    return EXIT_SUCCESS;
}
