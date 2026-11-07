/* Proves the license client's C interface from a C program linked against the static library: the
 * seal_client_options layout (each option set here shows up where it should), a check with nothing
 * saved, an activation request and a failed connection, an offline request file, and NULL arguments.
 * Usage: client <empty storage folder> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seal.h"

static int fails = 0;
#define EXPECT(cond, what) do { if (!(cond)) { printf("FAIL: %s\n", what); fails++; } } while (0)

static const char *KEY =
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEALiAdmTkGG9jtE74LHZzjfNugnNT9bIvVBRm0onTDGgQ=\n-----END PUBLIC KEY-----\n";
/* SHA-256 of "licensekit:studio:linux:0123456789abcdef0123456789abcdef". */
static const char *FINGERPRINT = "8c7043769cccf05ec444ab5786d1cc104b02e8379838f154db152cd25e01134d";

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <storage folder>\n", argv[0]); return 2; }
    seal_client_options options;
    seal_client_options_init(&options);
    EXPECT(options.grace_days < 0 && options.hardware == 1 && options.machine_id == NULL, "defaults");
    options.product = "studio";
    options.public_keys = KEY;
    options.storage_dir = argv[1];
    options.app_version = "9.9.9";
    options.sdk_name = "ctest";
    options.machine_id = "linux:0123456789abcdef0123456789abcdef";
    options.hardware = 0;
    seal_client *client = seal_client_new(&options);
    if (!client) { puts("FAIL: seal_client_new"); return 1; }
    EXPECT(strstr(seal_client_user_agent(client), "carcha-seal-native/") == seal_client_user_agent(client), "user agent prefix");
    EXPECT(strstr(seal_client_user_agent(client), "(ctest)") != NULL, "user agent sdk name");

    seal_result *r = seal_client_check_begin(client, 1800000000000.0);
    EXPECT(seal_result_kind(r) == SEAL_RESULT_DONE && seal_state_status(r) == SEAL_STATUS_UNLICENSED, "check with nothing saved");
    EXPECT(seal_state_flag(r, SEAL_FLAG_OFFLINE) == 0 && seal_state_feature_count(r) == 0, "unlicensed state");
    seal_result_free(r);

    r = seal_client_activate_begin(client, " lk-aaaa-bbbb ", NULL);
    EXPECT(seal_result_kind(r) == SEAL_RESULT_SEND, "activation needs the server");
    EXPECT(strcmp(seal_result_request_path(r), "/v1/activate") == 0, "activation path");
    const char *body = seal_result_request_body(r);
    EXPECT(strstr(body, "\"licenseKey\":\"LK-AAAA-BBBB\"") != NULL, "license key trimmed and upper case");
    EXPECT(strstr(body, FINGERPRINT) != NULL, "fingerprint from options.machine_id");
    EXPECT(strstr(body, "\"appVersion\":\"9.9.9\"") != NULL, "app version from options");
    EXPECT(strstr(body, "machineName") == NULL && strstr(body, "components") == NULL, "no machine name, no hardware");
    seal_result_free(r);
    r = seal_client_activate_finish(client, 0, NULL, 0, 1800000000000.0);
    EXPECT(seal_result_kind(r) == SEAL_RESULT_ERROR && strcmp(seal_result_error_code(r), "network") == 0, "no connection");
    seal_result_free(r);

    const char *refusal = "{\"error\":\"activation_limit\",\"message\":\"All seats are in use.\"}";
    r = seal_client_activate_begin(client, "LK-AAAA-BBBB", "Lab PC");
    seal_result_free(r);
    r = seal_client_activate_finish(client, 409, (const uint8_t *)refusal, strlen(refusal), 1800000000000.0);
    EXPECT(strcmp(seal_result_error_code(r), "activation_limit") == 0 && strcmp(seal_result_error_message(r), "All seats are in use.") == 0, "refusal");
    seal_result_free(r);

    r = seal_client_offline_request(client, "LK-AAAA-BBBB", "Lab PC");
    EXPECT(seal_result_kind(r) == SEAL_RESULT_DONE && strstr(seal_result_text(r), "licensekit-offline-request") != NULL, "offline request file");
    EXPECT(strstr(seal_result_text(r), "\"machineName\": \"Lab PC\"") != NULL, "machine name in the file");
    seal_result_free(r);

    r = seal_client_deactivate_offline(client);
    EXPECT(strcmp(seal_result_error_code(r), "unlicensed") == 0, "nothing to deactivate offline");
    seal_result_free(r);

    EXPECT(seal_client_activate_begin(client, NULL, NULL) == NULL, "NULL license key");
    EXPECT(seal_client_check_finish(client, 700, NULL, 0, 0) == NULL, "status out of range");
    EXPECT(seal_result_kind(NULL) == 0 && seal_state_status(NULL) == 0, "NULL result");
    seal_client_free(client);

    options.storage_dir = NULL;
    EXPECT(seal_client_new(&options) == NULL, "no storage folder");
    if (fails) return 1;
    printf("seal %s: license client through the C interface\nOK\n", seal_version());
    return 0;
}
