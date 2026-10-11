# argon

Small, typed Argon2id password hashing for slang services. Hashes use the
standard PHC string format, so they can be stored as text and verified by Go
or Zokor implementations that support Argon2id version 19.

## Install

```text
pkg argon git https://github.com/dolphlabs/argon.git tag v0.1.0 dir src/argon
```

After `v0.1.0` is tagged, run `slangc get` and import `argon`.

## Use

```slang
import "argon";

let encoded = argon.hash(password);
guard let stored = encoded else let e = err_of(encoded) {
    return err("could not hash password: " + e);
}

let checked = argon.verify(password, stored);
guard let matches = checked else {
    return err("stored password hash is invalid");
}
if !matches { return err("invalid credentials"); }
```

`hash` uses a fresh 16-byte cryptographic salt and returns a 32-byte tag in
`$argon2id$v=19$m=19456,t=2,p=1$...` form. The default cost is 19 MiB, two
passes, and one lane. This is OWASP's minimum Argon2id profile; benchmark your
own server and raise it with `new_params` / `hash_with` when your latency and
concurrent-memory budget allows.

```slang
let params_result = argon.new_params(65536, 3, 1);
guard let params = params_result else { return err("invalid Argon2 profile"); }
let upgraded = argon.hash_with(password, params);
```

Passwords are slang `str` values encoded as UTF-8 exactly as supplied. The
package does not normalize text or impose a minimum password length; the
application sets those policies. A mismatch returns `ok(false)`. Malformed
PHC strings and costs above the hard limits return `err` before KDF work.

After a successful `verify`, call `needs_rehash(encoded, desired)` to see
whether the stored cost profile should be upgraded. It only inspects the
encoded parameters; rehash with the plaintext password after verification.

## Bounds and runtime

- Supports only Argon2id version 19. It rejects other variants, versions,
  parameter orderings, duplicate/extra parameters, padded or non-canonical
  base64, and malformed values.
- Custom and parsed costs are capped at 256 MiB, 10 iterations, and 4 lanes.
  Passwords are capped at 1 MiB and encoded PHC strings at 512 bytes.
- The native KDF validates those bounds again and compares tags in constant
  time. OpenSSL owns its memory-hard workspace outside the slang GC; the
  package frees each EVP context after use and enables OpenSSL's `early_clean`
  option for password and secret context data. Derivation is synchronous and
  non-preemptible while OpenSSL runs, so each call occupies a slang worker.
  Each concurrent hash can use up to 256 MiB; rate-limit attempts and bound
  concurrency for both worker capacity and process memory.
- This package requires a slang compiler with native
  `crypto.argon2id_raw` and `crypto.argon2id_verify` support, plus OpenSSL 3.2
  or newer with the Argon2id provider. Older OpenSSL builds compile and return
  a clear unavailable error; existing crypto functions continue to work.

This package provides password hashing only. It does not add a pepper, choose
password policy, rate-limit requests, or decide account lockout behavior.

## Development

```sh
make test
make bench
```

The test fixture is an ordinary slang consumer. The benchmark uses matching
parameters and inputs for slang and Go, checks raw tag parity, and reports KDF
and wrapper costs separately.

A local microbenchmark on an Intel macOS laptop (Darwin 24.6, OpenSSL 3.6.4;
Go 1.24.1 with `golang.org/x/crypto` v0.31.0) used four ABBA rounds and 20
operations per process: 160 samples per operation and language. Both used
19,456 KiB, two iterations, one lane, a 32-byte tag, and the same password and
salt. Raw KDF tags matched byte-for-byte.

| Operation | slang p50 / p99 (ms) | Go p50 / p99 (ms) | Median batch ops/s, slang / Go |
|---|---:|---:|---:|
| Raw KDF | 37.45 / 71.20 | 31.78 / 39.25 | 26.1 / 31.1 |
| Full hash | 36.97 / 84.90 | 32.08 / 34.45 | 26.8 / 31.0 |
| Verify | 37.57 / 40.68 | 31.96 / 33.65 | 26.7 / 31.0 |

Peak process RSS was 23,308 KiB for slang and 61,876 KiB for Go. At this
profile, Go's median batch throughput was about 16-19% higher. This is a
single-process microbenchmark, not a server result. With 160 samples per
operation, p99 still reflects laptop noise; use it as an initial baseline,
not as a latency guarantee. Go uses its pure-Go KDF and slang uses OpenSSL,
so the comparison includes implementation differences as well as wrapper cost.

See [ARGON_PRD.md](ARGON_PRD.md) for the security boundary, acceptance tests,
and benchmark method. Defaults follow the [OWASP Password Storage Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html);
the format and algorithm follow [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).
