# Hardened image for the demo victim. The pedagogical point: none of this
# hardening (distroless, non-root, read-only rootfs, dropped caps) protects the
# *contents of process memory* from a privileged host observer. That protection
# is what a TDX trust domain adds — and this phase runs without TDX hardware.

# ---- build stage ------------------------------------------------------------
FROM gcc:13-bookworm AS build
WORKDIR /src
COPY victim.c .
# Static link so the runtime image needs no libc / shell / package manager.
RUN gcc -O2 -static -o victim victim.c && strip victim

# ---- runtime stage ----------------------------------------------------------
# distroless static: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/victim /victim
USER nonroot:nonroot
# The canary is NOT baked into this image. At runtime the binary reads it from
# the environment (see docker-compose.yml / run-victim.sh).
ENTRYPOINT ["/victim"]
