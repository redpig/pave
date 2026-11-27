/* The pave wallet for phone apps. See mobile/src/lib.rs.
 *
 * Open a wallet, then send it JSON commands with pave_call: the same
 * commands pave-node takes ({"cmd": "help"} lists them). Every string this
 * library returns is JSON and is the caller's to free with
 * pave_string_free. Replies carry "ok": true, or "ok": false and "error".
 */
#ifndef PAVE_H
#define PAVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PaveWallet PaveWallet;
typedef struct PaveJoin PaveJoin;

/* The app's keystore: on a phone, the platform's (Android Keystore, the
 * Secure Enclave). Each callback returns 0 on success, or 1 if `out` is
 * too small, with the length needed in *out_len; anything else fails.
 * seal: seal `data` under a fresh key, keeping older keys until commit.
 * open: open with any key not yet retired.
 * commit: retire every key but the newest. */
typedef struct {
    void *ctx;
    int (*seal)(void *ctx, const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *out_len);
    int (*open)(void *ctx, const uint8_t *sealed, size_t len, uint8_t *out, size_t cap, size_t *out_len);
    int (*commit)(void *ctx);
    /* Nonzero if an old copy of the state can't be opened after a commit. */
    int rollback_resistant;
} PaveKeystore;

char *pave_version(void);

/* Joining a town: begin makes this device's keys, in memory, and returns
 * {"request": hex} to take to the town; finish takes the town's reply (hex)
 * and creates the wallet at `path`. finish consumes `join`. */
PaveJoin *pave_join_begin(char **request_out);
PaveWallet *pave_join_finish(PaveJoin *join, const char *reply_hex, const char *name, const char *path, PaveKeystore ks, char **err);

/* Open a wallet: with the software keystore beside its state file (tests,
 * demos), or with the app's. Null on failure, with the error in *err. */
PaveWallet *pave_open(const char *path, char **err);
PaveWallet *pave_open_with(const char *path, PaveKeystore ks, char **err);

/* Run one JSON command. */
char *pave_call(PaveWallet *w, const char *json);

void pave_string_free(char *s);

/* Save and close. */
void pave_close(PaveWallet *w);

#ifdef __cplusplus
}
#endif

#endif
