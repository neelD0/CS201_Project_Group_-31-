#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATTERNS 25    // Maximum number of patterns
#define MAX_URL_LENGTH 256 // Maximum length of URL
#define ALPHABET_SIZE 256  // ASCII character set size

// Trie node structure
typedef struct TrieNode
{
    struct TrieNode *children[ALPHABET_SIZE];
    int is_end_of_pattern; // Marks end of a pattern
} TrieNode;

// Function to create a new trie node
TrieNode *create_node()
{
    TrieNode *node = (TrieNode *)malloc(sizeof(TrieNode));
    if (node == NULL) // Check for successful memory allocation
    {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }
    node->is_end_of_pattern = 0;
    for (int i = 0; i < ALPHABET_SIZE; i++)
        node->children[i] = NULL;
    return node;
}

// Insert a pattern into the trie
void insert_pattern(TrieNode *root, const char *pattern)
{
    TrieNode *node = root;
    for (int i = 0; i < strlen(pattern); i++)
    {
        int index = (unsigned char)pattern[i];
        if (!node->children[index])
            node->children[index] = create_node();

        node = node->children[index];
    }
    node->is_end_of_pattern = 1;
}

// Search for any pattern within the given URL
int search_patterns(TrieNode *root, const char *url)
{
    for (int i = 0; i < strlen(url); i++)
    {
        TrieNode *node = root;
        for (int j = i; j < strlen(url); j++)
        {
            int index = (unsigned char)url[j];
            if (!node->children[index])
                break;

            node = node->children[index];
            if (node->is_end_of_pattern)
                return 1; // Pattern found
        }
    }
    return 0; // No pattern matched
}

// Free trie memory
void free_trie(TrieNode *node)
{
    for (int i = 0; i < ALPHABET_SIZE; i++)
    {
        if (node->children[i])
            free_trie(node->children[i]);
    }
    free(node);
}

int main()
{
    // Create a root for the trie
    TrieNode *root = create_node();

    // List of known malicious patterns
    const char *malicious_patterns[MAX_PATTERNS] = {
        "free-prize.com", "login-security-update", "verify-account",
        "reset-password", "claim-reward", "bank-login", "confirm-email",
        "credit-card-update", "secure-login", "payment-required",
        "gift-card", "special-offer", "exclusive-deal", "security-alert",
        "account-suspended", "paypal-verification", "limited-time",
        "click-here", "confirm-purchase", "urgent-update",
        "winner-announcement", "malware-download", "phishing-attempt",
        "secure-update", "win-free"}; // Total 25 patterns

    // Insert all patterns into the trie
    for (int i = 0; i < MAX_PATTERNS; i++)
    {
        insert_pattern(root, malicious_patterns[i]);
    }

    // User input loop
    char url[MAX_URL_LENGTH];
    printf("Enter a URL to check if it's potentially malicious (enter '-1' to stop):\n");
    while (1)
    {
        printf("URL: ");
        if (!fgets(url, sizeof(url), stdin))
        {
            clearerr(stdin); // Clear any error in input stream
            continue;
        }

        url[strcspn(url, "\n")] = 0; // Remove newline character

        // Exit condition
        if (strcmp(url, "-1") == 0)
            break;

        // Check if the URL contains any malicious pattern
        if (search_patterns(root, url))
        {
            printf("Warning: Potentially malicious URL detected!\n");
        }
        else
        {
            printf("URL seems safe.\n");
        }
    }

    // Free trie memory
    free_trie(root);
    return 0;
}
