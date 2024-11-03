# Malicious URL Detection using Bloom Filter (CS201 Project) (Group 231)

This system leverages a Bloom filter to efficiently verify URLs against known malicious entries, using multiple hash functions—MurmurHash3, FNV-1a, DJB2, SDBM, and PJW. These hash functions set bits in a bit array, enabling quick detection ideal for real-time security. The URL database, stored in a CSV file named malicious_phish, is processed and saved in a compact binary format, facilitating high-speed lookups and allowing the system to manage extensive URL datasets effectively.

- **Dataset and Preprocessing**
The dataset includes URLs labeled as malicious, which are preprocessed for consistent formatting and minimal noise. Each URL is added to the Bloom filter during preprocessing, with the code for this phase saved in a C file named pre.

 - **Malicious URL Detection**
During detection, the binary bit array is loaded into memory. When a URL is entered, the system hashes it with each of the five functions to identify bit positions in the array. If all bits at the resulting indices are set, the URL is flagged as potentially malicious; otherwise, it’s deemed benign. The program takes URLs as input until -1 is entered to stop.

---

## Features

**False Positive Rate Calculation**
The Bloom filter’s probabilistic nature can lead to false positives—where URLs are flagged as malicious despite not being in the dataset. A benign URL dataset (benign.csv) was tested to observe this rate, finding 1.07% of benign URLs falsely flagged as malicious.

**False Negative Rate**
Bloom filters are designed to avoid false negatives. This was demonstrated by testing a fully malicious dataset, where all malicious URLs were correctly identified, confirming the absence of false negatives.

**Trie-Based Malicious URL Pattern Detection (Separate System Component)**
In addition to the Bloom filter, a Trie (prefix tree) is used to store known malicious URL patterns. The Trie structure enables efficient pattern matching, which can help detect harmful URLs that follow known malicious patterns but may not be directly flagged by the Bloom filter.

**Pattern Detection with Trie**
For each incoming URL, the Trie is searched for matching patterns. If a URL contains any of these harmful patterns, it is flagged as potentially malicious; otherwise, it is considered safe. This pattern-checking system complements the Bloom filter by adding an extra layer of precision, particularly for detecting URLs with common malicious patterns.
By integrating both the Bloom filter and Trie, this system balances the speed of probabilistic detection with the accuracy of pattern-based filtering for robust URL security.
---

## Requirements

- C Compiler

---

## Usage
1. Run pre.c file first, which will create a binary file named abc.
2. Run the main file which is bloom.c and continue entering urls from dataset.
3. As a separate application run trie.c file.
4. Input Pattern: The system accepts any URL for both Bloom filter and Trie-based checks, with -1 as the stop command. If the Trie identifies a pattern in the URL, it flags it as potentially malicious, adding depth to the detection process.

---

## Contributors

- **Aditya Khajuria** (2023MCB1323)
- **Shaurya Anant** (2023CSB1313)
- **Neelanjan Deshpande** (2023MCB1361)
