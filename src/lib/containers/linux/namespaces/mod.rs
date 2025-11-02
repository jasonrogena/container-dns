use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use libc::ino_t;
use nix::sched::CloneFlags;
use tracing::error;

const NAMESPACE_TYPE_NET: &str = "net";
const NAMESPACE_TYPE_UTS: &str = "uts";
const NAMESPACE_TYPE_MOUNT: &str = "mnt";
const NAMESPACE_TYPE_PID: &str = "pid";

#[derive(PartialEq, Eq)]
pub enum Type {
    Net,
    Uts,
    Mount,
    Pid,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An expected namespace is not available: {0}")]
    UnavailableNamespace(String),
}

#[derive(Debug)]
pub struct Namespaces {
    pub net_ino: ino_t,
    pub uts_ino: ino_t,
}

impl Namespaces {
    pub(crate) fn get_namespace_ino(
        ns_type: &Type,
        namespaces: &procfs::process::Namespaces,
    ) -> Result<ino_t, Error> {
        let namespace_name = Self::get_type_name(ns_type);
        let os_string: OsString = namespace_name.into();
        let ino: ino_t = match namespaces.0.get(&os_string) {
            Some(s) => s.identifier,
            None => {
                error!(
                    "No namespace named '{}' found in {:?}",
                    namespace_name, namespaces
                );
                return Err(Error::UnavailableNamespace(namespace_name.into()));
            }
        };

        Ok(ino)
    }

    fn get_type_name(ns_type: &Type) -> &str {
        match ns_type {
            Type::Net => NAMESPACE_TYPE_NET,
            Type::Uts => NAMESPACE_TYPE_UTS,
            Type::Mount => NAMESPACE_TYPE_MOUNT,
            Type::Pid => NAMESPACE_TYPE_PID,
        }
    }

    pub fn get_proc_path(pid: i32, ns_type: &Type) -> PathBuf {
        let path = match ns_type {
            Type::Net => format!("/proc/{}/ns/net", pid),
            Type::Uts => format!("/proc/{}/ns/uts", pid),
            Type::Mount => format!("/proc/{}/ns/mnt", pid),
            Type::Pid => format!("/proc/{}/ns/pid", pid),
        };

        Path::new(path.as_str()).to_path_buf()
    }

    pub fn get_clone_flags(ns_type: &Type) -> CloneFlags {
        match ns_type {
            Type::Net => CloneFlags::CLONE_NEWNET,
            Type::Uts => CloneFlags::CLONE_NEWUTS,
            Type::Mount => CloneFlags::CLONE_NEWNS,
            Type::Pid => CloneFlags::CLONE_NEWPID,
        }
    }
}
