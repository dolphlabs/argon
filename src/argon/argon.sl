// Argon2id password hashing with bounded PHC parsing.
import "crypto";
import "encoding";
import "strings";

pub let DEFAULT_MEMORY_KIB = 19456;
pub let DEFAULT_ITERATIONS = 2;
pub let DEFAULT_PARALLELISM = 1;
pub let DEFAULT_SALT_BYTES = 16;
pub let DEFAULT_TAG_BYTES = 32;

let MAX_MEMORY_KIB = 262144;
let MAX_ITERATIONS = 10;
let MAX_PARALLELISM = 4;
let MAX_PASSWORD_BYTES = 1048576;
let MAX_ENCODED_BYTES = 512;
let MAX_SALT_BYTES = 64;
let MAX_TAG_BYTES = 64;

pub struct Params {
    memory_kib: int,
    iterations: int,
    parallelism: int
}

struct ParsedHash {
    params: Params,
    salt: bytes,
    tag: bytes
}

pub fn default_params() -> Params {
    return Params {
        memory_kib: DEFAULT_MEMORY_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM
    };
}

// Custom costs are bounded so one stored hash cannot request unlimited work.
pub fn new_params(memory_kib: int, iterations: int, parallelism: int)
                  -> result[Params, str] {
    let params = Params {
        memory_kib: memory_kib,
        iterations: iterations,
        parallelism: parallelism
    };
    let valid = check_params(params);
    guard let _ok = valid else let message = err_of(valid) {
        return err(message);
    }
    return ok(params);
}

// Hash stores a PHC string: algorithm, version, costs, random salt, and tag.
// The password is UTF-8 exactly as supplied; the caller owns any normalization
// policy and should enforce minimum password length separately.
pub fn hash(password: str) -> result[str, str] {
    return hash_with(password, default_params());
}

pub fn hash_with(password: str, params: Params) -> result[str, str] {
    let valid = check_params(params);
    guard let _ok = valid else let message = err_of(valid) {
        return err(message);
    }
    if len(password) > MAX_PASSWORD_BYTES {
        return err("argon password exceeds the 1 MiB limit");
    }

    let salt_result = crypto.rand(DEFAULT_SALT_BYTES);
    guard let salt = salt_result else let message = err_of(salt_result) {
        return err(message);
    }
    let tag_result = crypto.argon2id_raw(
        to_bytes(password), salt, params.iterations, params.memory_kib,
        params.parallelism, DEFAULT_TAG_BYTES);
    guard let tag = tag_result else let message = err_of(tag_result) {
        return err(message);
    }

    let encoded = "$argon2id$v=19$m=" + to_str(params.memory_kib) +
        ",t=" + to_str(params.iterations) +
        ",p=" + to_str(params.parallelism) +
        "$" + encode_phc_base64(salt) + "$" + encode_phc_base64(tag);
    return ok(encoded);
}

// A password mismatch is ok(false). Malformed or over-budget encodings are
// errors, and are rejected before the memory-hard KDF is entered.
pub fn verify(password: str, encoded: str) -> result[bool, str] {
    if len(password) > MAX_PASSWORD_BYTES {
        return err("argon password exceeds the 1 MiB limit");
    }
    let parsed_result = parse_hash(encoded);
    guard let parsed = parsed_result else let message = err_of(parsed_result) {
        return err(message);
    }

    let verified = crypto.argon2id_verify(
        to_bytes(password), parsed.salt, parsed.tag,
        parsed.params.iterations, parsed.params.memory_kib,
        parsed.params.parallelism);
    guard let matches = verified else let message = err_of(verified) {
        return err(message);
    }
    return ok(matches);
}

// Check after successful verify; true means the stored record differs from
// this profile and should be replaced with hash_with(password, desired).
pub fn needs_rehash(encoded: str, desired: Params) -> result[bool, str] {
    let valid = check_params(desired);
    guard let _ok = valid else let message = err_of(valid) {
        return err(message);
    }
    let parsed_result = parse_hash(encoded);
    guard let parsed = parsed_result else let message = err_of(parsed_result) {
        return err(message);
    }
    return ok(parsed.params.memory_kib != desired.memory_kib ||
        parsed.params.iterations != desired.iterations ||
        parsed.params.parallelism != desired.parallelism ||
        len(parsed.salt) != DEFAULT_SALT_BYTES ||
        len(parsed.tag) != DEFAULT_TAG_BYTES);
}

fn check_params(params: Params) -> result[bool, str] {
    if params.parallelism < 1 || params.parallelism > MAX_PARALLELISM {
        return err("argon parallelism must be between 1 and 4");
    }
    if params.iterations < 1 || params.iterations > MAX_ITERATIONS {
        return err("argon iterations must be between 1 and 10");
    }
    if params.memory_kib < 8 * params.parallelism ||
       params.memory_kib > MAX_MEMORY_KIB {
        return err("argon memory must be between 8 * parallelism and 262144 KiB");
    }
    return ok(true);
}

fn parse_hash(encoded: str) -> result[ParsedHash, str] {
    if len(encoded) == 0 || len(encoded) > MAX_ENCODED_BYTES {
        return err("invalid Argon2id PHC string size");
    }
    let fields = strings.split(encoded, "$");
    if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" ||
       fields[2] != "v=19" {
        return err("invalid Argon2id PHC format or version");
    }

    let costs = strings.split(fields[3], ",");
    if len(costs) != 3 || !strings.has_prefix(costs[0], "m=") ||
       !strings.has_prefix(costs[1], "t=") ||
       !strings.has_prefix(costs[2], "p=") {
        return err("Argon2id PHC costs must be m,t,p in that order");
    }
    let memory_text = strings.slice(costs[0], 2, len(costs[0]));
    let iterations_text = strings.slice(costs[1], 2, len(costs[1]));
    let parallelism_text = strings.slice(costs[2], 2, len(costs[2]));
    let memory_result = parse_decimal(memory_text);
    guard let memory_kib = memory_result else {
        return err("invalid Argon2id memory cost");
    }
    let iterations_result = parse_decimal(iterations_text);
    guard let iterations = iterations_result else {
        return err("invalid Argon2id iteration count");
    }
    let parallelism_result = parse_decimal(parallelism_text);
    guard let parallelism = parallelism_result else {
        return err("invalid Argon2id parallelism");
    }
    let params_result = new_params(memory_kib, iterations, parallelism);
    guard let params = params_result else {
        return err("Argon2id PHC costs exceed the allowed limits");
    }

    let salt_result = decode_phc_base64(fields[4]);
    guard let salt = salt_result else {
        return err("invalid Argon2id salt encoding");
    }
    if len(salt) < 8 || len(salt) > MAX_SALT_BYTES {
        return err("Argon2id salt must contain 8 to 64 bytes");
    }
    let tag_result = decode_phc_base64(fields[5]);
    guard let tag = tag_result else {
        return err("invalid Argon2id tag encoding");
    }
    if len(tag) < 16 || len(tag) > MAX_TAG_BYTES {
        return err("Argon2id tag must contain 16 to 64 bytes");
    }
    return ok(ParsedHash { params: params, salt: salt, tag: tag });
}

fn parse_decimal(text: str) -> result[int, str] {
    if len(text) == 0 || len(text) > 10 {
        return err("invalid decimal value");
    }
    let parsed = to_int(text);
    guard let value = parsed else {
        return err("invalid decimal value");
    }
    if value < 0 || to_str(value) != text {
        return err("decimal value is not canonical");
    }
    return ok(value);
}

fn encode_phc_base64(raw: bytes) -> str {
    let encoded = encoding.base64_encode(raw);
    let padding = 0;
    if len(raw) % 3 == 1 {
        padding = 2;
    } else if len(raw) % 3 == 2 {
        padding = 1;
    }
    if padding == 0 { return encoded; }
    return strings.slice(encoded, 0, len(encoded) - padding);
}

fn decode_phc_base64(encoded: str) -> result[bytes, str] {
    if len(encoded) == 0 || len(encoded) > 88 || len(encoded) % 4 == 1 {
        return err("invalid PHC base64 length");
    }
    let padded = encoded;
    if len(padded) % 4 == 2 {
        padded = padded + "==";
    } else if len(padded) % 4 == 3 {
        padded = padded + "=";
    }
    let decoded_result = encoding.base64_decode(padded);
    guard let decoded = decoded_result else {
        return err("invalid PHC base64");
    }
    if encode_phc_base64(decoded) != encoded {
        return err("non-canonical PHC base64");
    }
    return ok(decoded);
}
