/* Proves the C interface from a C program linked against the static library: every lease
 * vector (from vectors_tsv) gives the core library's result, and the device and hardware
 * calls work. Usage: verify <vectors.tsv> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seal.h"

#define MAX_FIELDS 9

static char *unescape_newlines(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && r[1] == 'n') { *w++ = '\n'; r += 2; } else { *w++ = *r++; }
    }
    *w = 0;
    return s;
}

static int split(char *line, char **fields) {
    int n = 0;
    line[strcspn(line, "\r\n")] = 0;
    for (char *p = line; n < MAX_FIELDS; n++) {
        fields[n] = p;
        char *tab = strchr(p, '\t');
        if (!tab) { n++; break; }
        *tab = 0;
        p = tab + 1;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <vectors.tsv>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 2; }

    static char line[1 << 16];
    if (!fgets(line, sizeof line, f)) { puts("FAIL: empty file"); return 1; }
    line[strcspn(line, "\r\n")] = 0;
    seal_keys *keys = seal_keys_new(unescape_newlines(line));
    if (!keys || seal_keys_count(keys) != 1) { puts("FAIL: seal_keys_new"); return 1; }

    int count = 0, failed = 0;
    while (fgets(line, sizeof line, f)) {
        char *field[MAX_FIELDS];
        if (split(line, field) != MAX_FIELDS) { printf("FAIL: bad line %d\n", count + 1); return 1; }
        seal_check check;
        seal_check_init(&check);
        check.product = field[2];
        check.fingerprint_hash = field[3];
        if (strcmp(field[4], "-") != 0) check.issuer = field[4];
        check.now = strtod(field[5], NULL);
        if (strcmp(field[6], "-") != 0) check.grace_seconds = strtod(field[6], NULL);
        if (strcmp(field[7], "-") != 0) check.leeway_seconds = strtod(field[7], NULL);

        char kid[64];
        int32_t r = seal_verify_lease(keys, field[1], &check, kid, sizeof kid);
        char got[128];
        if (r == SEAL_OK) snprintf(got, sizeof got, "ok:%s", kid);
        else snprintf(got, sizeof got, "%s", seal_result_name(r));
        if (strcmp(got, field[8]) != 0) {
            printf("FAIL: %s: got %s, expected %s\n", field[0], got, field[8]);
            failed++;
        }
        count++;
    }
    fclose(f);
    seal_keys_free(keys);
    if (failed || count < 40) { printf("FAIL: %d of %d vectors\n", failed, count); return 1; }

    char device_key[44];
    int32_t d = seal_device_public_key("studio", device_key, sizeof device_key);
    if (d != SEAL_OK && d != SEAL_E_NO_DEVICE_KEY) { printf("FAIL: seal_device_public_key %d\n", d); return 1; }

    size_t needed = 0;
    if (seal_hardware("studio", NULL, 0, &needed) != SEAL_E_BUFFER || needed == 0) { puts("FAIL: seal_hardware size"); return 1; }
    char *hardware = malloc(needed + 64);
    if (seal_hardware("studio", hardware, needed + 64, &needed) != SEAL_OK || strncmp(hardware, "{\"format\":1,", 12) != 0) {
        puts("FAIL: seal_hardware");
        return 1;
    }
    free(hardware);

    printf("seal %s: %d lease vectors match the core library; device key %s\nOK\n", seal_version(), count,
           d == SEAL_OK ? "present" : "not available on this machine");
    return 0;
}
