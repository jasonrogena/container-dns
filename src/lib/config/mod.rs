use crate::dns::server::ServerConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An io Error was thrown while reading the config")]
    Io(#[from] io::Error),
    #[error("An Error was thrown while trying to parse the config as TOML")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    pub dns_server: ServerConfig,
}

impl Config {
    #[allow(dead_code)]
    pub fn new(config_path: &String) -> std::result::Result<Config, Error> {
        let contents = fs::read_to_string(config_path)?;

        Ok(toml::from_str(&contents)?)
    }
}
