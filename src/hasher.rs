use crypto::password_hash::SaltString;
use rand_core::OsRng;

#[cfg(feature = "argon2")]
pub type Hasher = argon2::Argon2<'static>;
#[cfg(feature = "scrypt")]
pub type Hasher = scrypt::Scrypt;

pub fn hasher() -> Hasher {
    #[cfg(feature = "argon2")]
    return argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 16, 1, Some(32)).unwrap(),
    );
    #[cfg(feature = "scrypt")]
    return scrypt::Scrypt;
}

pub fn salt() -> SaltString {
    SaltString::generate(OsRng)
}
