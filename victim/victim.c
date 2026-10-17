/*
 * victim.c — a stand-in production workload for the TDX confidentiality demo.
 *
 * It loads a *planted demo canary* into memory and then sleeps. The canary is a
 * fake, well-known value used only to show whether an observer can read process
 * memory. On a normal VM/container a privileged host observer can read these
 * bytes; against a TDX trust domain the same read returns ciphertext.
 *
 * Production practice: the canary is NOT hardcoded in this binary. It is read
 * at startup from the environment, which the runtime injects (compose
 * `environment:` / `docker run -e`). The same binary therefore carries no
 * secret of its own.
 *
 *   DB_PASSWORD   the canary credential
 *   DEMO_MARKER   the stable demo marker
 *
 * There is nothing sensitive in the source — the value is supplied at runtime.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Read a required value from the environment into a freshly allocated, resident
 * buffer. Fails fast (production behaviour) if the variable is unset or empty —
 * a real service must not start half-configured.
 *
 * The caller owns the returned buffer; we intentionally never free it so the
 * value stays resident in memory for the lifetime of the process.
 */
static char *load_from_env(const char *name, size_t *out_len)
{
    const char *val = getenv(name);
    if (val == NULL || val[0] == '\0') {
        fprintf(stderr,
                "[svc] FATAL: required environment variable %s is not set\n",
                name);
        exit(1);
    }

    size_t n = strlen(val);
    char *buf = malloc(n + 1);
    if (buf == NULL) {
        fprintf(stderr, "[svc] FATAL: out of memory reading %s\n", name);
        exit(1);
    }
    memcpy(buf, val, n + 1);

    *out_len = n;
    return buf;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Load the canary + marker from the environment. We keep them resident but
     * deliberately never log them, their lengths, or anything hinting the
     * process holds a canary -- a realistic workload would not advertise that,
     * and the demo must find the data in memory, not from the logs. */
    size_t secret_len = 0, marker_len = 0;
    volatile char *secret = (volatile char *)load_from_env("DB_PASSWORD", &secret_len);
    volatile char *marker = (volatile char *)load_from_env("DEMO_MARKER", &marker_len);

    /* Benign, service-style logging only. */
    printf("[svc] starting server; pid=%d\n", (int)getpid());
    printf("[svc] server listening; ready to accept requests\n");

    /* Touch the pages periodically so they stay resident and are not
     * optimized away. We never print the secret itself. */
    volatile unsigned long tick = 0;
    for (;;) {
        volatile char a = secret[tick % secret_len];
        volatile char b = marker[tick % marker_len];
        (void)a;
        (void)b;
        tick++;
        printf("[svc] server running; uptime=%lus\n", tick * 5);
        sleep(5);
    }

    return 0;
}
