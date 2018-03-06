#[derive(Serialize, Deserialize, Debug)]
pub struct SecretMeta {
    pub mona: MonaMeta,
    pub plaintext: PlaintextMeta,
    pub kdf: KDFMeta,
    pub encrypt: EncryptMeta,
    pub paranoid: ParanoidMeta
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonaMeta {
    pub version: String,
    pub encoding: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PlaintextMeta {
    pub min_bits: i32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KDFMeta {
    pub name: String,
    pub algo: String,
    pub iters: i32,
    pub salt: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptMeta {
    pub name: String,
    pub algo: String,
    pub nonce: String,
    pub keylen: i32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ParanoidMeta {
}
