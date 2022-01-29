use crate::permit::Permit;
use cosmwasm_std::{Api, Binary, CanonicalAddr, HumanAddr, StdResult, Uint128};
use ripemd160::{Digest, Ripemd160};
use schemars::JsonSchema;
use secret_toolkit::crypto::sha_256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PermitSignature {
    pub pub_key: PubKey,
    pub signature: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PubKey {
    /// ignored, but must be "tendermint/PubKeySecp256k1" otherwise the verification will fail
    pub r#type: String,
    /// Secp256k1 PubKey
    pub value: Binary,
}

impl PubKey {
    pub fn new(pubkey: Binary) -> Self {
        Self {
            r#type: "tendermint/PubKeySecp256k1".to_string(),
            value: pubkey,
        }
    }
}

pub struct PubKeyValue(pub Binary);

impl PubKeyValue {
    pub fn as_canonical(&self) -> CanonicalAddr {
        let mut hasher = Ripemd160::new();
        hasher.update(sha_256(&self.0 .0));
        CanonicalAddr(Binary(hasher.finalize().to_vec()))
    }

    pub fn as_humanaddr<A: Api>(&self, api: &A) -> StdResult<HumanAddr> {
        api.human_address(&self.as_canonical())
    }
}

#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TxMsg<T> {
    pub r#type: String,
    pub value: T,
}

impl<T: Clone + Serialize> TxMsg<T> {
    pub fn new(params: T, msg_type: Option<String>) -> Self {
        Self {
            r#type: msg_type.unwrap_or("signature_proof".to_string()),
            value: params.clone(),
        }
    }
}

#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SignedTx<T> {
    /// ignored
    pub account_number: Uint128,
    /// ignored, no Env in query
    pub chain_id: String,
    /// ignored
    pub fee: Fee,
    /// ignored
    pub memo: String,
    /// the signed message
    pub msgs: Vec<TxMsg<T>>,
    /// ignored
    pub sequence: Uint128,
}

impl<T: Clone + Serialize> SignedTx<T> {
    pub fn from_permit(permit: &Permit<T>, msg_type: Option<String>) -> Self {
        Self {
            account_number: permit.account_number.unwrap_or(Uint128::zero()),
            chain_id: permit.chain_id.clone().unwrap_or("secret-4".to_string()),
            fee: Default::default(),
            memo: permit.memo.clone().unwrap_or(String::new()),
            msgs: vec![TxMsg::new(permit.params.clone(), msg_type)],
            sequence: permit.sequence.unwrap_or(Uint128::zero()),
        }
    }
}

#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: Uint128,
}

impl Default for Fee {
    fn default() -> Self {
        Self {
            amount: vec![Coin::default()],
            gas: Uint128(1),
        }
    }
}

#[remain::sorted]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Coin {
    pub amount: Uint128,
    pub denom: String,
}

impl Default for Coin {
    fn default() -> Self {
        Self {
            amount: Uint128::zero(),
            denom: "uscrt".to_string(),
        }
    }
}
