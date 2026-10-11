import "argon";
import "crypto";
import "encoding";
import "time";

let iterations = 20;
let password = b"benchmark-password";
let salt = b"bench-salt-12345";
let params = argon.default_params();

let raw_setup = crypto.argon2id_raw(
    password, salt, params.iterations, params.memory_kib,
    params.parallelism, argon.DEFAULT_TAG_BYTES);
guard let raw_tag = raw_setup else let message = err_of(raw_setup) {
    panic("argon raw setup failed: " + message);
}
println("RAW " + encoding.hex_encode(raw_tag));

let token_result = argon.hash_with(to_str(password), params);
guard let token = token_result else { panic("argon hash setup failed"); }
let warm_verify = argon.verify(to_str(password), token);
guard let warm_matches = warm_verify else { panic("argon verify setup failed"); }
if !warm_matches { panic("argon verify setup mismatch"); }

let raw_samples: [int] = [];
let raw_checksum = 0;
let raw_batch_start = time.mono();
for i in 0..iterations {
    let started = time.mono();
    let derived = crypto.argon2id_raw(
        password, salt, params.iterations, params.memory_kib,
        params.parallelism, argon.DEFAULT_TAG_BYTES);
    let finished = time.mono();
    guard let tag = derived else { panic("argon raw benchmark failed"); }
    raw_checksum = raw_checksum + tag[0];
    let elapsed: duration = finished - started;
    push(raw_samples, elapsed as int);
}
let raw_batch_elapsed: duration = time.mono() - raw_batch_start;

let hash_samples: [int] = [];
let hash_checksum = 0;
let hash_batch_start = time.mono();
for i in 0..iterations {
    let started = time.mono();
    let generated = argon.hash_with(to_str(password), params);
    let finished = time.mono();
    guard let encoded = generated else { panic("argon hash benchmark failed"); }
    hash_checksum = hash_checksum + len(encoded);
    let elapsed: duration = finished - started;
    push(hash_samples, elapsed as int);
}
let hash_batch_elapsed: duration = time.mono() - hash_batch_start;

let verify_samples: [int] = [];
let verify_checksum = 0;
let verify_batch_start = time.mono();
for i in 0..iterations {
    let started = time.mono();
    let checked = argon.verify(to_str(password), token);
    let finished = time.mono();
    guard let matches = checked else { panic("argon verify benchmark failed"); }
    if !matches { panic("argon verify benchmark mismatch"); }
    verify_checksum = verify_checksum + 1;
    let elapsed: duration = finished - started;
    push(verify_samples, elapsed as int);
}
let verify_batch_elapsed: duration = time.mono() - verify_batch_start;

println("B R " + to_str(raw_batch_elapsed as int));
for i in 0..len(raw_samples) { println("R " + to_str(raw_samples[i])); }
println("B H " + to_str(hash_batch_elapsed as int));
for i in 0..len(hash_samples) { println("H " + to_str(hash_samples[i])); }
println("B V " + to_str(verify_batch_elapsed as int));
for i in 0..len(verify_samples) { println("V " + to_str(verify_samples[i])); }
println("C " + to_str(raw_checksum + hash_checksum + verify_checksum));
