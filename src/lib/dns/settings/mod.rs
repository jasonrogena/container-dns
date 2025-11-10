use std::{collections::HashSet, time::Duration};

use ipnet::IpNet;

#[derive(Clone, Debug)]
pub struct RecordTtls {
    pub(crate) srv: Duration,
    pub(crate) a: Duration,
    pub(crate) ns: Duration,
}

impl Default for RecordTtls {
    fn default() -> Self {
        Self {
            srv: Duration::from_secs(60),
            a: Duration::from_secs(60),
            ns: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub(crate) record_ttls: RecordTtls,
    pub(crate) allowed_networks: HashSet<IpNet>,
    pub(crate) refresh_interval: Duration,
}
