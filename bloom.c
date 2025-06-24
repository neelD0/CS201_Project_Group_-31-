#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

#define BIT_ARRAY_SIZE 1816463
#define MAX_URL_LENGTH 1000
#define SAMPLE_SIZE 100000 // Maximum sample size for calculating false positive rate

uint8_t *bit_array;

uint32_t murmurhash3(const void *key, int len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t h = seed ^ (len * 0x5bd1e995);
    const uint32_t prime = 0x5bd1e995;
    for (int i = 0; i < len; i++)
    {
        h ^= data[i];
        h *= prime;
        h ^= h >> 13;
    }
    h ^= h >> 15;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

uint32_t fnv_hash(const void *key, size_t len)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t hash = 2166136261u;
    const uint32_t prime = 16777619u;
    for (size_t i = 0; i < len; i++)
    {
        hash ^= data[i];
        hash *= prime;
    }
    hash ^= hash >> 16;
    hash *= 0x85ebca6bu;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35u;
    hash ^= hash >> 16;
    return hash;
}

uint32_t djb2(const char *str)
{
    uint32_t hash_value = 5381;
    while (*str)
    {
        hash_value = ((hash_value << 5) + hash_value) ^ (uint32_t)(*str);
        str++;
    }
    return hash_value;
}

uint32_t sdbm(const char *str)
{
    uint32_t hash = 0;
    int c;
    while ((c = *str++))
    {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

uint32_t pjw(const char *str)
{
    uint32_t hash = 0;
    uint32_t high;
    while (*str)
    {
        hash = (hash << 4) + (*str++);
        high = hash & 0xF0000000;
        if (high)
        {
            hash ^= high >> 24;
            hash &= ~high;
        }
    }
    return hash;
}

void set_bit(int index)
{
    bit_array[index / 8] |= (1 << (index % 8));
}

int check_bit(int index)
{
    return (bit_array[index / 8] & (1 << (index % 8))) != 0;
}

int is_malicious(const char *url)
{
    size_t len = strlen(url);
    uint32_t hash1 = murmurhash3(url, len, 1) % BIT_ARRAY_SIZE;
    uint32_t hash2 = fnv_hash(url, len) % BIT_ARRAY_SIZE;
    uint32_t hash3 = djb2(url) % BIT_ARRAY_SIZE;
    uint32_t hash4 = sdbm(url) % BIT_ARRAY_SIZE;
    uint32_t hash5 = pjw(url) % BIT_ARRAY_SIZE;
    return check_bit(hash1) && check_bit(hash2) && check_bit(hash3) &&
           check_bit(hash4) && check_bit(hash5);
}

void trim_trailing_whitespace(char *str)
{
    int len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1]))
    {
        str[len - 1] = '\0';
        len--;
    }
}

void calculate_false_positive_rate(const char *filename)
{    
    printf("\n[INFO] False Positive: A benign (safe) URL is incorrectly flagged as malicious by the Bloom filter.\n");
    printf("[INFO] True Negative: A benign (safe) URL is correctly identified as not malicious.\n\n");
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening benign URLs file!\n");
        return;
    }

    int false_positives = 0;
    int true_negatives = 0;
    char line[MAX_URL_LENGTH + 20]; // Adjust size if lines are long
    char benign_url[MAX_URL_LENGTH];

    int count = 0;
    while (fgets(line, sizeof(line), file) && count < SAMPLE_SIZE)
    {
        line[strcspn(line, "\n")] = 0; // Remove newline character

        // Find the last comma in the line
        char *last_comma = strrchr(line, ',');
        if (last_comma != NULL)
        {
            *last_comma = '\0';             // Terminate the string at the last comma
            trim_trailing_whitespace(line); // Trim any spaces at the end of the URL
        }

        strncpy(benign_url, line, MAX_URL_LENGTH);

        if (is_malicious(benign_url))
        {
            false_positives++;
        }
        else
        {
            true_negatives++;
        }
        count++;
    }

    fclose(file);

    double false_positive_rate = ((double)false_positives / (false_positives + true_negatives)) * 100;
    printf("\nTesting on file: %s\n", filename);
    printf("False Positive Rate: %.6f\n", false_positive_rate);
    printf("Number of False Positives: %d\n", false_positives);
    printf("Number of True Negatives: %d\n", true_negatives);
}

void calculate_false_negative_rate(const char *filename)
{    
    printf("\n[INFO] False Negative: A malicious URL is incorrectly flagged as safe by the Bloom filter.\n");
    printf("[INFO] True Positive: A malicious URL is correctly identified as malicious.\n\n");
    
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening malicious URLs file!\n");
        return;
    }

    int true_positives = 0;
    int false_negatives = 0;
    char line[MAX_URL_LENGTH + 20]; // Adjust size if lines are long
    char malware_url[MAX_URL_LENGTH];

    int count = 0;
    while (fgets(line, sizeof(line), file) && count < 9997)
    {
        line[strcspn(line, "\n")] = 0; // Remove newline character

        // Find the last comma in the line
        char *last_comma = strrchr(line, ',');
        if (last_comma != NULL)
        {
            *last_comma = '\0';             // Terminate the string at the last comma
            trim_trailing_whitespace(line); // Trim any spaces at the end of the URL
        }

        strncpy(malware_url, line, MAX_URL_LENGTH);

        if (is_malicious(malware_url))
        {
            true_positives++;
        }
        else
        {
            false_negatives++;
            printf("%s \n", malware_url);
        }
        count++;
    }

    fclose(file);

    double false_negative_rate = ((double)false_negatives / (true_positives + false_negatives)) * 100;
    printf("\nTesting on file: %s\n", filename);
    printf("False Negative Rate: %.6f\n", false_negative_rate);
    printf("Number of True Positives: %d\n", true_positives);
    printf("Number of False Negatives: %d\n", false_negatives);
}

int main()
{
    bit_array = (uint8_t *)calloc((BIT_ARRAY_SIZE / 8), sizeof(uint8_t));
    if (bit_array == NULL)
    {
        printf("Memory allocation failed!\n");
        return 1;
    }

    FILE *in_file = fopen("abc", "rb");
    if (in_file == NULL)
    {
        printf("Error opening binary file for reading!\n");
        free(bit_array);
        return 1;
    }

    fread(bit_array, sizeof(uint8_t), BIT_ARRAY_SIZE / 8, in_file);
    fclose(in_file);

    calculate_false_positive_rate("benign.csv");
    calculate_false_negative_rate("malicious.csv");

    char url[MAX_URL_LENGTH];
    printf("Enter URLs to check if they are malicious (enter -1 to stop):\n");
    while (1)
    {
        if (!fgets(url, sizeof(url), stdin))
            break;
        url[strcspn(url, "\n")] = 0;
        if (strcmp(url, "-1") == 0)
            break;
        if (is_malicious(url))
        {
            printf("Potentially malicious URL\n");
        }
        else
        {
            printf("Not malicious URL\n");
        }
    }

    free(bit_array);
    return 0;
}
