use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Group {
    pub version: String,
    pub accounts: Vec<Account>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    pub username: String,
    pub password: String
}

impl Group {
    pub fn empty() -> Group {
        Group {
            version: String::from("0.0.1"),
            accounts: Vec::new()
        }
    }

    pub fn from_toml_bytes(bytes: &Vec<u8>) -> Result<Group, String> {
        toml::from_slice(&bytes)
            .map_err(|e| format!("Failed to read account group from TOML: {:?}", e))
    }

    pub fn to_toml_bytes(&self) -> Result<Vec<u8>, String> {
        toml::to_vec(&self)
            .map_err(|e| format!("Failed to serialize account group {:?}", e))
    }
}
