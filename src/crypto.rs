use data_encoding::{Encoding, HEXLOWER};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const OUTPUT_LEN: usize = 32; // SHA256 output

/// Hash a password using PBKDF2-HMAC-SHA256.
pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN];
    pbkdf2_hmac::<Sha256>(secret, salt, iterations, &mut out);
    out
}

/// Verify a password hash using PBKDF2-HMAC-SHA256.
pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let result = hash_password(secret, salt, iterations);
    ct_eq(&result, previous)
}


/// Return an array holding `N` random bytes.
pub fn get_random_bytes<const N: usize>() -> [u8; N] {
    let mut array = [0u8; N];
    getrandom::getrandom(&mut array).expect("Error generating random values");
    array
}

/// Encode random bytes using the provided encoding.
pub fn encode_random_bytes<const N: usize>(e: &Encoding) -> String {
    e.encode(&get_random_bytes::<N>())
}

/// Generate a random alphanumeric string.
pub fn get_random_string_alphanum(num_chars: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let random_bytes = get_random_bytes::<64>();
    (0..num_chars)
        .map(|i| {
            let idx = random_bytes[i % 64] as usize % ALPHABET.len();
            char::from(ALPHABET[idx])
        })
        .collect()
}

/// Generate a hex-encoded random ID.
pub fn generate_id<const N: usize>() -> String {
    encode_random_bytes::<N>(&HEXLOWER)
}

/// Generate a personal API key (30 alphanumeric characters).
pub fn generate_api_key() -> String {
    get_random_string_alphanum(30)
}

/// Constant-time equality comparison.
pub fn ct_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> bool {
    use subtle::ConstantTimeEq;
    a.as_ref().ct_eq(b.as_ref()).into()
}
