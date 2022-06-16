use sha2::{Digest, Sha256};
use std::convert::TryInto;

pub trait ViewingKey<const KEY_SIZE: usize>: ToString {
    fn compare_hashes(s1: &[u8], s2: &[u8]) -> bool {
        s1.eq(s2)
    }

    fn compare(&self, hashed: &[u8]) -> bool {
        Self::compare_hashes(&self.hash(), hashed)
    }

    fn hash(&self) -> [u8; KEY_SIZE] {
        Sha256::digest(self.to_string().as_bytes())
            .as_slice()
            .try_into()
            .expect("Incorrect password length")
    }
}

#[cfg(test)]
mod viewing_key_tests {
    use crate::viewing_keys::ViewingKey;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    struct Key(pub String);

    impl ToString for Key {
        fn to_string(&self) -> String {
            self.0.clone()
        }
    }

    impl ViewingKey<32> for Key {}

    #[test]
    fn hash_creation() {
        let pwd = Key("password".to_string());

        let hashed = pwd.hash();

        assert_eq!(hashed.len(), 32)
    }

    #[test]
    fn hash_comparing() {
        let pwd = Key("password".to_string());
        let hashed = pwd.hash();

        assert!(pwd.compare(&hashed));
        assert!(Key::compare_hashes(
            &hashed,
            &Key("password".to_string()).hash()
        ));

        let wrong_pwd = Key("wrong_password".to_string());
        let wrong_hashed = wrong_pwd.hash();

        for i in 0..32 {
            assert_ne!(hashed[i], wrong_hashed[i]);
        }
        assert!(!pwd.compare(&wrong_hashed));
        assert!(!Key::compare_hashes(&hashed, &wrong_hashed));
    }
}
