/* Proves the C interface from a C program linked against the static library. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "licensekit_hwid.h"

int main(void) {
    const uint8_t key[] = "product-a";
    size_t key_len = sizeof key - 1;

    if (lk_hwid_collect(NULL, 1, NULL, 0) != LK_HWID_E_ARGS) { puts("FAIL: NULL key accepted"); return 1; }

    intptr_t n = lk_hwid_collect(key, key_len, NULL, 0);
    if (n <= 0) { printf("FAIL: size query returned %ld\n", (long)n); return 1; }

    char *buf = NULL;
    for (;;) {
        buf = realloc(buf, (size_t)n + 1);
        intptr_t m = lk_hwid_collect(key, key_len, buf, (size_t)n + 1);
        if (m < 0) { printf("FAIL: error %ld\n", (long)m); return 1; }
        if (m <= n) { n = m; break; }
        n = m;
    }
    if (strlen(buf) != (size_t)n || strncmp(buf, "{\"format\":1,", 12) != 0) { printf("FAIL: %s\n", buf); return 1; }
    printf("version %s\n%s\nOK\n", lk_hwid_version(), buf);
    free(buf);
    return 0;
}
