use std::{collections::HashSet, time::Duration};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordTtls {
    pub(crate) srv: Duration,
    pub(crate) a: Duration,
    pub(crate) aaaa: Duration,
    pub(crate) ns: Duration,
    // `ptr` and `txt` carry serde defaults so that config files written before
    // DNS-SD browse/metadata support still parse.
    #[serde(default = "default_ptr_txt_ttl")]
    pub(crate) ptr: Duration,
    #[serde(default = "default_ptr_txt_ttl")]
    pub(crate) txt: Duration,
}

fn default_ptr_txt_ttl() -> Duration {
    Duration::from_secs(60)
}

impl Default for RecordTtls {
    fn default() -> Self {
        Self {
            srv: Duration::from_secs(60),
            a: Duration::from_secs(60),
            aaaa: Duration::from_secs(60),
            ns: Duration::from_secs(3600),
            ptr: default_ptr_txt_ttl(),
            txt: default_ptr_txt_ttl(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub(crate) record_ttls: RecordTtls,
    pub(crate) allowed_record_networks: HashSet<IpNet>,
    pub(crate) refresh_interval: Duration,
}
