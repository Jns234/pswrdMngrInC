#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

#define main cli_main
#include "cliPassMngr.c"
#undef main

// ---------- Simple test harness ----------
// inspiration from here: https://github.com/squarewave/labrat

typedef int (*test_fn)(void);

typedef struct {
    const char *name;
    test_fn fn;
} test_case;

static int tests_run = 0;
static int tests_failed = 0;

static int assert_true(int expr, const char *expr_str, const char *file, int line) {
    if (!expr) {
        fprintf(stderr, "[FAIL] %s:%d: assertion failed: %s\n", file, line, expr_str);
        return 0;
    }
    return 1;
}

#define ASSERT_TRUE(e) \
    do { \
        if (!assert_true((e), #e, __FILE__, __LINE__)) return 1; \
    } while (0)

#define ASSERT_STREQ(a, b) \
    do { \
        if (strcmp((a), (b)) != 0) { \
            fprintf(stderr, "[FAIL] %s:%d: strings not equal:\n  '%s'\n  '%s'\n", \
                    __FILE__, __LINE__, (a), (b)); \
            return 1; \
        } \
    } while (0)

static int run_test(const test_case *tc) {
    tests_run++;
    int rc = tc->fn();
    if (rc != 0) {
        tests_failed++;
        fprintf(stderr, "[FAIL] %s\n", tc->name);
    } else {
        printf("[ OK ] %s\n", tc->name);
    }
    return rc;
}

// ---------- Tests ----------

// 1) url_encode / url_decode roundtrip

static int test_url_roundtrip_basic(void) {
    const char *inputs[] = {
        "",
        "abcXYZ123",
        "hello world",
        "email+tag@example.com",
        "symbols !@#$%^&*()[]{}",
        "üñíçødé",
    };

    for (size_t i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
        const char *s = inputs[i];
        char *enc = url_encode((char *)s);
        ASSERT_TRUE(enc != NULL);

        char *dec = url_decode(enc);
        ASSERT_TRUE(dec != NULL);

        ASSERT_STREQ(s, dec);

        free(enc);
        free(dec);
    }

    return 0;
}

// 2) encrypt / decrypt roundtrip

static int test_encrypt_decrypt_roundtrip(void) {
    unsigned char key[KEY_BYTES];
    randombytes_buf(key, sizeof key);

    const char *plaintext = "MyS3cretP@ss!";
    unsigned long long plen = (unsigned long long)strlen(plaintext);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 256];
    unsigned char decrypted[256];

    ASSERT_TRUE(plen < 256);

    int erc = encrypt((const unsigned char *)plaintext, plen,
                      key, nonce, ciphertext);
    ASSERT_TRUE(erc == 0);

    int drc = decrypt(decrypted,
                      ciphertext, crypto_secretbox_MACBYTES + plen,
                      nonce, key);
    ASSERT_TRUE(drc == 0);

    decrypted[plen] = '\0';
    ASSERT_STREQ(plaintext, (char *)decrypted);

    return 0;
}

// 3) decrypt with wrong key should fail

static int test_decrypt_wrong_key_fails(void) {
    unsigned char key1[KEY_BYTES];
    unsigned char key2[KEY_BYTES];
    randombytes_buf(key1, sizeof key1);
    randombytes_buf(key2, sizeof key2);

    const char *plaintext = "AnotherSecret!";
    unsigned long long plen = (unsigned long long)strlen(plaintext);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 256];
    unsigned char decrypted[256];

    ASSERT_TRUE(plen < 256);

    ASSERT_TRUE(encrypt((const unsigned char *)plaintext, plen,
                        key1, nonce, ciphertext) == 0);

    int drc = decrypt(decrypted,
                      ciphertext, crypto_secretbox_MACBYTES + plen,
                      nonce, key2);

    ASSERT_TRUE(drc != 0);

    return 0;
}

// 4) decrypt with tampered ciphertext should fail

static int test_decrypt_tampered_cipher_fails(void) {
    unsigned char key[KEY_BYTES];
    randombytes_buf(key, sizeof key);

    const char *plaintext = "TamperMe";
    unsigned long long plen = (unsigned long long)strlen(plaintext);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 256];
    unsigned char decrypted[256];

    ASSERT_TRUE(plen < 256);

    ASSERT_TRUE(encrypt((const unsigned char *)plaintext, plen,
                        key, nonce, ciphertext) == 0);

    size_t clen = crypto_secretbox_MACBYTES + plen;

    ciphertext[clen / 2] ^= 0x01;  // flip a bit

    int drc = decrypt(decrypted,
                      ciphertext, clen,
                      nonce, key);

    ASSERT_TRUE(drc != 0);

    return 0;
}

// 5) Boundary test: max-length plaintext under SAVED_PASSWORD_LEN

static int test_encrypt_max_length_under_limit(void) {
    char buf[SAVED_PASSWORD_LEN];
    memset(buf, 'A', SAVED_PASSWORD_LEN - 1);
    buf[SAVED_PASSWORD_LEN - 1] = '\0';

    unsigned long long plen = (unsigned long long)strlen(buf);
    ASSERT_TRUE(plen == SAVED_PASSWORD_LEN - 1);

    unsigned char key[KEY_BYTES];
    randombytes_buf(key, sizeof key);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[crypto_secretbox_MACBYTES + SAVED_PASSWORD_LEN];
    unsigned char decrypted[SAVED_PASSWORD_LEN];

    ASSERT_TRUE(encrypt((const unsigned char *)buf, plen,
                        key, nonce, ciphertext) == 0);

    ASSERT_TRUE(decrypt(decrypted, ciphertext,
                        crypto_secretbox_MACBYTES + plen,
                        nonce, key) == 0);

    decrypted[plen] = '\0';
    ASSERT_STREQ(buf, (char *)decrypted);

    return 0;
}

// ---------- Test registry ----------

static const test_case tests[] = {
    { "url_roundtrip_basic",             test_url_roundtrip_basic },
    { "encrypt_decrypt_roundtrip",       test_encrypt_decrypt_roundtrip },
    { "decrypt_wrong_key_fails",         test_decrypt_wrong_key_fails },
    { "decrypt_tampered_cipher_fails",   test_decrypt_tampered_cipher_fails },
    { "encrypt_max_length_under_limit",  test_encrypt_max_length_under_limit },
};

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        run_test(&tests[i]);
    }

    printf("\nTests run: %d, failed: %d\n", tests_run, tests_failed);

    return tests_failed ? 1 : 0;
}
