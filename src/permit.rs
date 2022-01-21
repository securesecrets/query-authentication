use crate::transaction::{PermitSignature, PubKeyValue, SignedTx, TxMsg};
use bech32::FromBase32;
use cosmwasm_std::{to_binary, Binary, CanonicalAddr, StdError, StdResult, Uint128};
use schemars::JsonSchema;
use secp256k1::Secp256k1;
use secret_toolkit::crypto::sha_256;
use serde::{Deserialize, Serialize};

// NOTE: Struct order is very important for signatures

// Signature idea taken from https://github.com/scrtlabs/secret-toolkit/blob/token-permits/packages/permit/src/funcs.rs

/// Where the information will be stored
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Permit<T: Clone + Serialize> {
    pub params: Option<T>,
    pub signature: PermitSignature,
    pub account_number: Option<Uint128>,
    pub chain_id: Option<String>,
    pub sequence: Option<Uint128>,
    pub memo: Option<String>,
}

pub fn bech32_to_canonical(addr: &str) -> CanonicalAddr {
    let (_, data, _) = bech32::decode(addr).unwrap();
    CanonicalAddr(Binary(Vec::<u8>::from_base32(&data).unwrap()))
}

impl<T: Clone + Serialize> Permit<T> {
    pub fn create_signed_tx(&self, msg_type: Option<String>) -> SignedTx<T> {
        SignedTx::from_permit(&self, msg_type)
    }

    /// Returns the permit signer
    pub fn validate(&self, msg_type: Option<String>) -> StdResult<PubKeyValue> {
        Permit::validate_signed_tx(&self.signature, &self.create_signed_tx(msg_type))
    }

    pub fn validate_signed_tx(signature: &PermitSignature, signed_tx: &SignedTx<T>) -> StdResult<PubKeyValue> {
        let pubkey = &signature.pub_key.value;

        // Validate signature
        let signed_bytes = to_binary(signed_tx)?;
        let signed_bytes_hash = sha_256(signed_bytes.as_slice());
        let secp256k1_msg = secp256k1::Message::from_slice(&signed_bytes_hash).map_err(|err| {
            StdError::generic_err(format!(
                "Failed to create a secp256k1 message from signed_bytes: {:?}",
                err
            ))
        })?;

        let secp256k1_verifier = Secp256k1::verification_only();

        let secp256k1_signature =
            secp256k1::Signature::from_compact(&signature.signature.0)
                .map_err(|err| StdError::generic_err(format!("Malformed signature: {:?}", err)))?;
        let secp256k1_pubkey = secp256k1::PublicKey::from_slice(pubkey.0.as_slice())
            .map_err(|err| StdError::generic_err(format!("Malformed pubkey: {:?}", err)))?;

        secp256k1_verifier
            .verify(&secp256k1_msg, &secp256k1_signature, &secp256k1_pubkey)
            .map_err(|err| {
                StdError::generic_err(format!(
                    "Failed to verify signatures for the given permit: {:?}",
                    err
                ))
            })?;

        Ok(PubKeyValue(pubkey.clone()))
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::transaction::PubKey;
    use cosmwasm_std::Uint128;

    #[remain::sorted]
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    struct TestPermitMsg {
        pub address: String,
        pub some_number: Uint128,
    }

    type TestPermit = Permit<TestPermitMsg>;

    const ADDRESS: &str = "secret102nasmxnxvwp5agc4lp3flc6s23335xm8g7gn9";
    const PUBKEY: &str = "A0qzJ3s16OKUfn1KFyh533vBnBOQIT0jm+R/FBobJCfa";
    const SIGNED_TX: &str =
        "4pZtghyHKHHmwiGNC5JD8JxCJiO+44j6GqaLPc19Q7lt85tr0IRZHYcnc0pkokIds8otxU9rcuvPXb0+etLyVA==";

    // Use secretcli tx sign-doc file --from account
    //{
    //  "account_number": "0",
    //  "chain_id": "pulsar-1",
    //  "fee": {
    //      "amount": [{
    //          "amount": "0",
    //          "denom": "uscrt"
    //      }],
    //      "gas": "1"
    //  },
    //  "memo": "",
    //  "msgs": [{
    //      "type": "signature_proof",
    //      "value": {
    //          "address": "secret102nasmxnxvwp5agc4lp3flc6s23335xm8g7gn9",
    //          "some_number": "10"
    //      }
    //  }],
    //  "sequence": "0"
    // }

    #[test]
    fn test_signed_tx() {
        let permit = TestPermit {
            params: Some(TestPermitMsg {
                address: ADDRESS.to_string(),
                some_number: Uint128(10),
            }),
            chain_id: Some("pulsar-1".to_string()),
            sequence: None,
            signature: PermitSignature {
                pub_key: PubKey::new(Binary::from_base64(PUBKEY).unwrap()),
                signature: Binary::from_base64(SIGNED_TX).unwrap(),
            },
            account_number: None,
            memo: None
        };

        let addr = permit.validate(None).unwrap();
        assert_eq!(addr.as_canonical(), bech32_to_canonical(ADDRESS));
    }
}
