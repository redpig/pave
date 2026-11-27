/* Join a town and use the wallet through pave.h, with the app's own
 * keystore callbacks, as a phone app would.
 *
 *   smoke <request-file> <reply-file> <state-path>
 *
 * Phase 1 (no reply file yet): writes the join request and waits for the
 * town's reply to appear. The keystore here is a stand-in that "seals" by
 * prefixing a version byte and keeps every version until commit; a real
 * app calls its platform keystore. */
#include "pave.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXV 64
static struct {
    uint8_t live[MAXV];
    uint8_t next;
    int commits;
} ks_state = {{0}, 1, 0};

static int seal(void *ctx, const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    (void)ctx;
    *out_len = len + 1;
    if (cap < len + 1) return 1;
    uint8_t v = ks_state.next++;
    ks_state.live[v % MAXV] = 1;
    out[0] = v;
    memcpy(out + 1, data, len);
    return 0;
}

static int open_(void *ctx, const uint8_t *sealed, size_t len, uint8_t *out, size_t cap, size_t *out_len) {
    (void)ctx;
    if (len < 1 || !ks_state.live[sealed[0] % MAXV]) return 2;
    *out_len = len - 1;
    if (cap < len - 1) return 1;
    memcpy(out, sealed + 1, len - 1);
    return 0;
}

static int commit(void *ctx) {
    (void)ctx;
    for (int i = 0; i < MAXV; i++) ks_state.live[i] = (i == (uint8_t)(ks_state.next - 1) % MAXV);
    ks_state.commits++;
    return 0;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *s = malloc(n + 1);
    fread(s, 1, n, f);
    s[n] = 0;
    fclose(f);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' ')) s[--n] = 0;
    return s;
}

static void say(const char *what, char *json) {
    printf("%s %s\n", what, json);
    fflush(stdout);
    pave_string_free(json);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: smoke <request-file> <reply-file> <state-path>\n");
        return 2;
    }
    PaveKeystore ks = {NULL, seal, open_, commit, 0};
    say("version", pave_version());

    char *req = NULL;
    PaveJoin *join = pave_join_begin(&req);
    FILE *f = fopen(argv[1], "w");
    fputs(req, f);
    fclose(f);
    pave_string_free(req);
    printf("request written; waiting for the town's reply\n");
    fflush(stdout);
    char *reply = NULL;
    for (int i = 0; i < 600 && !(reply = slurp(argv[2])); i++) usleep(100000);
    if (!reply) return 3;

    char *err = NULL;
    PaveWallet *w = pave_join_finish(join, reply, "phone", argv[3], ks, &err);
    free(reply);
    if (!w) {
        say("join failed", err);
        return 4;
    }
    say("whoami", pave_call(w, "{\"cmd\":\"whoami\"}"));
    say("bad", pave_call(w, "{\"cmd\":\"no such command\"}"));
    say("json", pave_call(w, "not json"));
    pave_close(w);

    /* Keep a copy of the state as it is now, a stale backup. */
    char old[4096];
    snprintf(old, sizeof old, "%s.old", argv[3]);
    char *bytes = NULL;
    FILE *in = fopen(argv[3], "rb");
    fseek(in, 0, SEEK_END);
    long n = ftell(in);
    fseek(in, 0, SEEK_SET);
    bytes = malloc(n);
    fread(bytes, 1, n, in);
    fclose(in);
    FILE *o = fopen(old, "wb");
    fwrite(bytes, 1, n, o);
    fclose(o);
    free(bytes);

    /* Reopen through the same keystore: the state opens under its newest
     * key, and the next save retires the key the stale copy was under. */
    w = pave_open_with(argv[3], ks, &err);
    if (!w) {
        say("reopen failed", err);
        return 5;
    }
    say("again", pave_call(w, "{\"cmd\":\"whoami\"}"));
    pave_close(w);
    PaveWallet *stale = pave_open_with(old, ks, &err);
    if (stale) {
        printf("stale opened\n");
        return 6;
    }
    say("stale", err);
    printf("commits %d\n", ks_state.commits);
    return 0;
}
