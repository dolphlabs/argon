import "argon";
import "strings";

fn require(ok: bool, what: str) {
    if !ok { panic("argon test failed: " + what); }
}

fn is_error[T](value: result[T, str]) -> bool {
    if let _ok = value { return false; }
    return true;
}

fn error_is[T](value: result[T, str], expected: str) -> bool {
    guard let _ok = value else let message = err_of(value) {
        return message == expected;
    }
    return false;
}

let defaults = argon.default_params();
require(defaults.memory_kib == 19456 && defaults.iterations == 2 &&
        defaults.parallelism == 1, "default profile");
let go_vector = argon.verify(
    "password",
    "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$Ze622Xop9o0ck8nk4gBJyst6XfiYWx22DFdy1IzGWsY");
guard let go_vector_matches = go_vector else {
    panic("Go x/crypto PHC vector was rejected");
}
require(go_vector_matches, "Go x/crypto PHC interoperability");
println("Go x/crypto PHC interoperability ok");
let custom_result = argon.new_params(32, 2, 1);
guard let custom = custom_result else { panic("valid custom profile rejected"); }
let custom_hash_result = argon.hash_with("pāssword", custom);
guard let custom_hash = custom_hash_result else {
    panic("custom hash failed");
}
require(strings.has_prefix(custom_hash, "$argon2id$v=19$m=32,t=2,p=1$"),
        "PHC prefix and costs");
require(!strings.has_suffix(custom_hash, "="), "PHC base64 is unpadded");
let custom_hash_again_result = argon.hash_with("pāssword", custom);
guard let custom_hash_again = custom_hash_again_result else {
    panic("second custom hash failed");
}
require(custom_hash != custom_hash_again, "random salt uniqueness");
let match_result = argon.verify("pāssword", custom_hash);
guard let matches = match_result else { panic("valid hash rejected"); }
require(matches, "correct password");
let mismatch_result = argon.verify("wrong", custom_hash);
guard let mismatch = mismatch_result else { panic("mismatch returned an error"); }
require(!mismatch, "wrong password");
println("custom PHC hash and verify ok");

let default_hash_result = argon.hash("default profile password");
guard let default_hash = default_hash_result else {
    panic("default hash failed");
}
let default_verify_result = argon.verify("default profile password", default_hash);
guard let default_matches = default_verify_result else {
    panic("default hash could not be verified");
}
require(default_matches, "default profile verify");
let unchanged = argon.needs_rehash(default_hash, defaults);
guard let rehash = unchanged else { panic("default rehash check failed"); }
require(!rehash, "current default does not need rehash");
let upgrade = argon.needs_rehash(custom_hash, defaults);
guard let needs_upgrade = upgrade else { panic("upgrade check failed"); }
require(needs_upgrade, "custom profile needs upgrade");
println("default profile and rehash check ok");

require(is_error(argon.new_params(7, 1, 1)), "minimum memory bound");
require(is_error(argon.new_params(262145, 1, 1)), "maximum memory bound");
require(is_error(argon.new_params(8, 0, 1)), "minimum iteration bound");
require(is_error(argon.new_params(8, 11, 1)), "maximum iteration bound");
require(is_error(argon.new_params(8, 1, 0)), "minimum parallelism bound");
require(is_error(argon.new_params(8, 1, 5)), "maximum parallelism bound");
require(error_is(argon.verify("p", "$argon2i$v=19$m=32,t=1,p=1$YWJjZGVmZ2hpamts$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                 "invalid Argon2id PHC format or version"),
        "wrong variant rejected");
require(error_is(argon.verify("p", "$argon2id$v=16$m=32,t=1,p=1$YWJjZGVmZ2hpamts$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                 "invalid Argon2id PHC format or version"),
        "wrong version rejected");
require(error_is(argon.verify("p", "$argon2id$v=19$m=262145,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                 "Argon2id PHC costs exceed the allowed limits"),
        "cost cap is checked before derivation");
require(is_error(argon.verify("p", custom_hash + "=")),
        "padded base64 rejected");
require(is_error(argon.verify("p", strings.repeat("x", 513))),
        "encoded size bound");
require(is_error(argon.verify("p", "$argon2id$v=19$m=32,t=2,p=1$%%%$%%%")),
        "malformed base64 rejected");
println("cost bounds and malformed PHC rejected");
