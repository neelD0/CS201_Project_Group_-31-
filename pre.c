#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h> // For isspace

#define BIT_ARRAY_SIZE 1816463 // Size of the bit array in bits
#define MAX_URL_LENGTH 5000    // Maximum length for the URL

// Bit array for the Bloom filter
uint8_t *bit_array;

// MurmurHash3 function
uint32_t murmurhash3(const void *key, int len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t h = seed ^ (len * 0x5bd1e995); // Initial hash based on length and seed
    const uint32_t prime = 0x5bd1e995;      // Prime constant

    // Process each byte of the input
    for (int i = 0; i < len; i++)
    {
        h ^= data[i]; // XOR byte into hash
        h *= prime;   // Multiply by prime
        h ^= h >> 13; // Mix in the shifted bits
    }

    // Final mixing to ensure good distribution
    h ^= h >> 15;    // Mix again with a right shift
    h *= 0xc2b2ae35; // Another prime multiplication
    h ^= h >> 16;    // Final mix with another right shift

    return h;
}

// FNV-1a hash function
uint32_t fnv_hash(const void *key, size_t len)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t hash = 2166136261u;      // FNV offset basis
    const uint32_t prime = 16777619u; // FNV prime

    // Process each byte of the input
    for (size_t i = 0; i < len; i++)
    {
        hash ^= data[i]; // XOR the current byte into the hash
        hash *= prime;   // Multiply by FNV prime
    }

    // Additional mixing steps to enhance distribution
    hash ^= hash >> 16;  // XOR with bits shifted right 16
    hash *= 0x85ebca6bu; // Mix with a different prime
    hash ^= hash >> 13;  // XOR with bits shifted right 13
    hash *= 0xc2b2ae35u; // Another mixing step with a different prime
    hash ^= hash >> 16;  // Final mix with right shift 16

    return hash;
}

// DJB2 hash function
uint32_t djb2(const char *str)
{
    uint32_t hash_value = 5381;
    while (*str)
    {
        hash_value = ((hash_value << 5) + hash_value) ^ (uint32_t)(*str); // hash * 33 XOR c
        str++;
    }
    return hash_value;
}

// SDBM hash function
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

// PJW hash function
uint32_t pjw(const char *str)
{
    uint32_t hash = 0;
    uint32_t high;

    while (*str)
    {
        hash = (hash << 4) + (*str++); // Shift left by 4 bits and add the character

        high = hash & 0xF0000000; // Extract high bits using a mask
        if (high)
        {                       // If high bits are non-zero
            hash ^= high >> 24; // XOR high bits shifted down
            hash &= ~high;      // Clear high bits
        }
    }

    return hash;
}

// Function to set a bit in the bit array
void set_bit(int index)
{
    if (index >= BIT_ARRAY_SIZE || index < 0)
    {
        printf("Index out of bounds: %d\n", index);
        return;
    }
    bit_array[index / 8] |= (1 << (index % 8));
}

// Function to check if a bit is set in the bit array
int is_bit_set(int index)
{
    if (index >= BIT_ARRAY_SIZE || index < 0)
    {
        return 0;
    }
    return (bit_array[index / 8] & (1 << (index % 8))) != 0;
}

// Function to add a URL to the Bloom filter
void add_url(const char *url)
{
    size_t len = strlen(url);

    // Generate indices using multiple hash functions
    uint32_t hash1 = murmurhash3(url, len, 1) % BIT_ARRAY_SIZE;
    uint32_t hash2 = fnv_hash(url, len) % BIT_ARRAY_SIZE;
    uint32_t hash3 = djb2(url) % BIT_ARRAY_SIZE;
    uint32_t hash4 = sdbm(url) % BIT_ARRAY_SIZE;
    uint32_t hash5 = pjw(url) % BIT_ARRAY_SIZE;

    // Debugging: Print hash values
    // printf("Adding URL: %s\n", url);
    // printf("Hashes: %u, %u, %u, %u, %u\n", hash1, hash2, hash3, hash4, hash5);

    // Set bits in the bit array
    set_bit(hash1);
    set_bit(hash2);
    set_bit(hash3);
    set_bit(hash4);
    set_bit(hash5);
}

// Function to check if a URL is potentially in the Bloom filter
int check_url(const char *url)
{
    size_t len = strlen(url);

    // Generate indices using the same hash functions
    uint32_t hash1 = murmurhash3(url, len, 1) % BIT_ARRAY_SIZE;
    uint32_t hash2 = fnv_hash(url, len) % BIT_ARRAY_SIZE;
    uint32_t hash3 = djb2(url) % BIT_ARRAY_SIZE;
    uint32_t hash4 = sdbm(url) % BIT_ARRAY_SIZE;
    uint32_t hash5 = pjw(url) % BIT_ARRAY_SIZE;

    // Check bits in the bit array
    return is_bit_set(hash1) && is_bit_set(hash2) &&
           is_bit_set(hash3) && is_bit_set(hash4) &&
           is_bit_set(hash5);
}

// Helper function to trim whitespace from both ends of a string
void trim_whitespace(char *str)
{
    char *end;
    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)
        return; // All spaces

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    // Null-terminate after the last non-space character
    *(end + 1) = 0;
}

// Function to read URLs from a CSV file and add them to the Bloom filter
void read_urls_from_csv(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        return;
    }

    char line[512];

    char url[MAX_URL_LENGTH];

    while (fgets(line, sizeof(line), file))
    {
        line[strcspn(line, "\n")] = 0;

        char *url = strtok(line, ",");
        char *property = strtok(NULL, ",");

        if (property != NULL)
        {
            trim_whitespace(property); // Remove leading and trailing whitespace

            // Check for malicious properties
            if (strcmp(property, "phishing") == 0 || strcmp(property, "malware") == 0 ||
                strcmp(property, "defacement") == 0)
            {

                add_url(url);
            }
        }
    }

    fclose(file);
}

int main()
{
    bit_array = (uint8_t *)calloc((BIT_ARRAY_SIZE + 7) / 8, sizeof(uint8_t));
    if (bit_array == NULL)
    {
        printf("Memory allocation failed!\n");
        return 1;
    }

    read_urls_from_csv("malicious_phish.csv");

    FILE *out_file = fopen("abc", "wb");
    if (out_file == NULL)
    {
        printf("Error opening binary file for writing!\n");
        free(bit_array);
        return 1;
    }
    fwrite(bit_array, sizeof(uint8_t), (BIT_ARRAY_SIZE + 7) / 8, out_file);
    fclose(out_file);

    free(bit_array);
    printf("Preprocessing complete. Bit array written to 'abc'.\n");

    return 0;
}