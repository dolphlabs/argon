# Argon package PRD

## Goal

Build a standalone, source-only `argon` package for slang services that need
password hashing and verification. Keep its stored hashes interoperable with
Go and Zokor through the standard Argon2id PHC string format. Keep passwords,
salts, and derived tags in byte form at the native boundary; do not implement
Argon2 in slang source.

## v1 API

```slang
import "argon";

let encoded = argon.hash(password);
guard let stored = encoded else { return err("password hash failed"); }

let checked = argon.verify(password, stored);
guard let matches = checked else { return err("invalid password hash"); }
if !matches { return err("invalid credentials"); }
```

- `Params` contains `memory_kib`, `iterations`, and `parallelism`.
- `default_params()` returns 19,456 KiB, 2 iterations, and 1 lane.
- `new_params(memory_kib, iterations, parallelism)` validates a custom profile.
- `hash(password)` creates a random 16-byte salt and 32-byte tag.
- `hash_with(password, params)` uses a caller-selected validated profile.
- `verify(password, encoded)` returns `ok(false)` for a password mismatch and
  `err(...)` for malformed or out-of-policy encodings.
- `needs_rehash(encoded, desired)` checks the encoded parameters so callers can
  upgrade a hash after successful verification.

Passwords are slang `str` values encoded as UTF-8. The package emits and
accepts only Argon2id version 19 in PHC format. v1 fixes the salt at 16 bytes
and tag at 32 bytes for new hashes. Verification accepts tags of 16 through 64
bytes and salts of 8 through 64 bytes for compatible existing records.

## Bounds and security

- Argon2id only; do not select an algorithm from encoded input.
- Defaults follow OWASP's minimum Argon2id profile: 19 MiB, 2 iterations, and
  parallelism 1. Applications should benchmark their deployment and raise the
  cost where their latency and concurrency budget allows.
- Accept custom memory from `8 * parallelism` through 262,144 KiB, iterations
  from 1 through 10, and parallelism from 1 through 4. Apply the same ceilings
  before verifying an encoded hash; reject over-budget values before entering
  the KDF.
- Cap password input at 1 MiB and encoded PHC input at 512 bytes. Parse decimal
  parameters with overflow checks and require one canonical parameter set.
- Generate salts from `crypto.rand`; never accept caller-supplied salts in the
  password API.
- Native derivation uses OpenSSL's Argon2id KDF provider (OpenSSL 3.2 or newer),
  validates all lengths and costs again, and compares tags in constant time.
  It keeps the memory-hard workspace outside the slang GC heap and returns
  concise errors without password or hash contents.
- Applications must still rate-limit and bound concurrent verification. A
  per-call memory ceiling does not cap aggregate memory across concurrent
  requests.

## Implementation scope

- Package code lives in `src/argon/` and uses slang's `crypto`, `encoding`,
  and `strings` packages.
- Add the smallest low-level Argon2id hash/verify primitives to slang's existing
  `crypto` native package, backed by OpenSSL EVP_KDF. Do not add a second
  cryptographic implementation or a new system library dependency.
- Document the OpenSSL 3.2+ runtime requirement for Argon2id calls. Return an
  explicit error if the provider is unavailable; ordinary existing crypto
  calls must keep working with older supported OpenSSL versions.
- Include a consumer test, Argon2id known-answer vector, PHC interoperability
  check against Go, malformed-input and cost-bound tests, and GC verification.

## Performance evidence

Compare slang and Go on the same host using identical Argon2id parameters,
password bytes, salt, tag length, and version. Report raw samples and medians
for hash and verify p50/p99 latency, operations per second, peak RSS, and slang
GC allocations. Benchmark the underlying derivation separately from salt
creation and PHC formatting to distinguish KDF cost from wrapper overhead.

Final local result (Intel macOS, OpenSSL 3.6.4, Go 1.24.1 plus
`x/crypto` v0.31.0): four ABBA rounds with 20 operations per process produced
160 samples per operation and language. Raw/hash/verify slang p50 was
37.45/36.97/37.57 ms and Go p50 was 31.78/32.08/31.96 ms. Median batch
throughput was 26.1/26.8/26.7 ops/s for slang and 31.1/31.0/31.0 for Go.
Peak process RSS was 23,308 KiB for slang and 61,876 KiB for Go. p99 is in
the README table; it is laptop microbenchmark data, not cloud or server
tail-latency evidence.

## Standards and guidance

- [RFC 9106, Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OpenSSL EVP_KDF-ARGON2](https://docs.openssl.org/3.2/man7/EVP_KDF-ARGON2/)
