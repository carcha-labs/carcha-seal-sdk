/*
 * Carcha Seal hardware id: reads this machine's components and returns one
 * HMAC-SHA256 per component, keyed by your product. Raw serials never leave
 * the library.
 *
 * Link the static library (seal_hwid.lib / libseal_hwid.a) into
 * native apps, or load the shared one (.dll / .dylib / .so).
 */
#ifndef SEAL_HWID_H
#define SEAL_HWID_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Invalid arguments: key NULL or key_len 0, or out NULL with out_len != 0. */
#define LK_HWID_E_ARGS ((intptr_t)-1)
/* Internal error; nothing was written. */
#define LK_HWID_E_INTERNAL ((intptr_t)-2)

/* Library version, e.g. "0.1.0". Static string; do not free. */
const char *lk_hwid_version(void);

/*
 * Writes UTF-8 JSON plus a NUL terminator into out:
 *   {"format":1,"vm":false,"components":[{"kind":"disk","hash":"<64 hex>"},...]}
 * kind is one of: uuid, board, disk, mac, os, cpu, gpu.
 *
 * Returns the JSON length without the terminator. If the result is >= out_len,
 * nothing usable was written: call again with at least result + 1 bytes
 * (pass out = NULL, out_len = 0 to ask for the size). Hardware is read on each
 * call, so repeat until the result fits. Negative results are the errors above.
 */
intptr_t lk_hwid_collect(const uint8_t *key, size_t key_len, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SEAL_HWID_H */
