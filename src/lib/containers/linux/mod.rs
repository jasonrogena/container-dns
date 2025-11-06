use core::panic;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    ffi::OsString,
    fmt::Debug,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::exit,
    rc::Rc,
    sync::mpsc::RecvError,
};

use crate::containers::{self, Host, IpAddrType, linux::namespaces::Namespaces};
use libc::{ino_t, pid_t};
use nix::{
    errno,
    sys::{
        socket::{AddressFamily, SockaddrIn, SockaddrIn6, SockaddrLike},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{Pid, gethostname},
};
use nix::{
    fcntl::{OFlag, open},
    ifaddrs::getifaddrs,
    sched::setns,
    sys::stat::Mode,
    unistd::{ForkResult, fork},
};
use procfs::{ProcError, process::all_processes};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{debug, error, instrument, trace, warn};

pub mod namespaces;
pub mod process;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("A proc error was thrown while trying to get process information: {0}")]
    Proc(#[from] ProcError),
    #[error("A unix error number was thrown: {0}")]
    Errno(#[from] errno::Errno),
    #[error("An error was thrown while working with Linux process information: {0}")]
    Process(#[from] process::Error),
    #[error("An error was thrown while working with Linux namespace information: {0}")]
    Namespaces(#[from] namespaces::Error),
    #[error("A MPSC receive error was thrown: {0}")]
    MpscRecvError(#[from] RecvError),
    #[error("An I/O error was thrown: {0}")]
    Io(#[from] io::Error),
    #[error("A child process threw an error: {0}")]
    ChildProcess(#[from] ChildProcessError),
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum ChildProcessError {
    #[error("An error was thrown by the child process: {0}")]
    Generic(String),
    #[error("Thead did not return any data")]
    NoReturnThread(),
    #[error("A spawned child thread panicked")]
    ChildThreadPanic(),
    #[error("Could not deserialize data: {0}")]
    Deserialize(String),
}

fn get_ip_addresses(addr_type: Option<IpAddrType>) -> Result<HashSet<IpAddr>, errno::Errno> {
    let mut addresses: HashSet<IpAddr> = HashSet::new();
    let addrs = getifaddrs()?;
    for cur_addr in addrs {
        let addr_val = if let Some(v) = cur_addr.address {
            v
        } else {
            continue;
        };

        if addr_val.family() == Some(AddressFamily::Inet) {
            if let Some(IpAddrType::V6) = addr_type {
                continue;
            }
            // Convert the SockaddrStorage to SockaddrIn
            // This unwrap is safe because we checked the family is INET
            let sockaddr_in: &SockaddrIn = addr_val.as_sockaddr_in().unwrap();
            addresses.insert(IpAddr::V4(sockaddr_in.ip()));
        } else if addr_val.family() == Some(AddressFamily::Inet6) {
            if let Some(IpAddrType::V4) = addr_type {
                continue;
            }
            // Convert the SockaddrStorage to SockaddrIn6
            // This unwrap is safe because we checked the family is INET6
            let sockaddr_in: &SockaddrIn6 = addr_val.as_sockaddr_in6().unwrap();
            addresses.insert(IpAddr::V6(sockaddr_in.ip()));
        }
    }

    Ok(addresses)
}

fn json_serialize_child_process_data<T>(data: Result<T, ChildProcessError>) -> String
where
    T: Serialize,
{
    match serde_json::to_string(&data) {
        Ok(ok) => ok,
        Err(e) => {
            error!(
                "An error was thrown while trying to JSON serialize data: {:?}",
                e
            );
            "".to_string()
        }
    }
}

fn json_deserialize_child_process_data<T>(data: String) -> Result<T, ChildProcessError>
where
    T: for<'a> Deserialize<'a>,
{
    trace!("About to deserialize data: {}", data);
    match serde_json::from_str(&data) {
        Ok(ok) => ok,
        Err(e) => {
            error!(
                "An error was thrown while trying to JSON deserialize data: {:?}",
                e
            );
            Err(ChildProcessError::Deserialize(e.to_string()))
        }
    }
}

fn write_child_process_data_tcp<T>(data: Result<T, ChildProcessError>, addr: SocketAddr)
where
    T: Serialize,
{
    let json_data = json_serialize_child_process_data(data);
    match TcpStream::connect(addr) {
        Ok(mut s) => match s.write_all(json_data.as_bytes()) {
            Ok(_) => debug!("Wrote to TCP connection"),
            Err(e) => error!("An error occurred writing to to TCP stream: {:?}", e),
        },
        Err(e) => {
            error!("Could not write to to TCP stream: {:?}", e);
        }
    }
}

fn write_child_process_data_tmp<T>(data: Result<T, ChildProcessError>)
where
    T: Serialize,
{
    let path = format!("/tmp/container-dns-{}", std::process::id());
    debug!("About to write data to {}", path);
    let json_data = json_serialize_child_process_data(data);
    let mut file = match File::create(path.clone()) {
        Ok(f) => f,
        Err(e) => {
            error!(path = path, "Could not create file: {:?}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(json_data.as_bytes()) {
        error!(
            path = path,
            "An error was thrown while writing data into a file: {:?}", e
        );
    }
    if let Err(e) = file.sync_data() {
        error!(
            path = path,
            "An error was thrown while syncing data into a file: {:?}", e
        );
    }
}

fn write_child_process_data<T>(
    data: Result<T, ChildProcessError>,
    addr: SocketAddr,
    ns_type: namespaces::Type,
) where
    T: Serialize,
{
    match ns_type {
        namespaces::Type::Mount => write_child_process_data_tcp(data, addr),
        _ => write_child_process_data_tmp(data),
    }
}

fn read_child_process_data_tcp<T>(
    listener: &mut TcpListener,
) -> (Result<T, ChildProcessError>, bool)
where
    T: for<'a> Deserialize<'a>,
{
    let mut buf = String::new();
    debug!("About to read from TCP connection");

    if let Some(stream) = listener.incoming().next() {
        match stream {
            Ok(mut s) => {
                debug!("Detected a new TCP connection");
                match s.read_to_string(&mut buf) {
                    Ok(_) => {
                        return (json_deserialize_child_process_data(buf), false);
                    }
                    Err(e) => {
                        error!(
                            "An error occurred while reading data from TCP stream: {:?}",
                            e
                        );
                        return (Err(ChildProcessError::Generic(e.to_string())), false);
                    }
                }
            }
            Err(e) => {
                error!("Connection failed: {:?}", e);
                return (Err(ChildProcessError::Generic(e.to_string())), false);
            }
        }
    }

    (Err(ChildProcessError::NoReturnThread()), false)
}

fn read_child_process_data_tmp<T>(child_pid: pid_t) -> (Result<T, ChildProcessError>, bool)
where
    T: for<'a> Deserialize<'a>,
{
    wait_for_child(child_pid);
    let path = format!("/tmp/container-dns-{}", child_pid);
    debug!("About to read from file {}", path);
    let result = match fs::read_to_string(path.clone()) {
        Ok(data) => (json_deserialize_child_process_data(data), true),
        Err(e) => {
            error!(
                path = path,
                "An error was thrown while recieving data from a child process: {:?}", e
            );
            (Err(ChildProcessError::Generic(e.to_string())), true)
        }
    };
    if let Err(e) = fs::remove_file(path.clone()) {
        error!(
            path = path,
            "An error was thrown while removing a temporary file: {:?}", e
        );
    }

    result
}

fn read_child_process_data<T>(
    listener: &mut TcpListener,
    child_pid: pid_t,
    ns_type: namespaces::Type,
) -> Result<T, ChildProcessError>
where
    T: for<'a> Deserialize<'a>,
{
    let (result, child_reaped) = match ns_type {
        namespaces::Type::Mount => read_child_process_data_tcp(listener),
        _ => read_child_process_data_tmp(child_pid),
    };
    if !child_reaped {
        // To avoid zombie child processes
        wait_for_child(child_pid);
    }

    result
}

fn wait_for_child(child_pid: pid_t) {
    debug!("Waiting for child process to exit {:?}", child_pid);
    loop {
        match waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::empty())) {
            Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                debug!("Child PID {} has returned", child_pid);
                break;
            }
            Err(e) => {
                error!("Child process {} has errored with: {:?}", child_pid, e);
                break;
            }
            _ => {}
        }
    }
}

fn run_in_namespace<F, T, S>(
    pid: i32,
    ns_type: namespaces::Type,
    input: S,
    closure: F,
) -> Result<T, ChildProcessError>
where
    F: FnOnce(S) -> Result<T, ChildProcessError> + Send + 'static,
    T: Send + Debug + Serialize + for<'a> Deserialize<'a> + 'static,
    S: Send + 'static,
{
    let expected_pid = std::process::id();
    let mut listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| ChildProcessError::Generic(e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| ChildProcessError::Generic(e.to_string()))?;
    debug!("Host firing a new TCP connection on: {:?}", addr);

    // Using unsafe fork() instead of a more idiomatic approach (like thread::spawn) because
    // Linux doesn't permit running setns() against a mount namespace from a multithreaded
    // process
    let result = match unsafe { fork().map_err(|e| ChildProcessError::Generic(e.to_string()))? } {
        ForkResult::Parent { child } => {
            debug!(
                child_pid = child.as_raw(),
                "Waiting for child process to return response"
            );
            read_child_process_data(&mut listener, child.as_raw(), ns_type)
        }
        ForkResult::Child => {
            debug!(
                current_pid = std::process::id(),
                "Isolated child process for setns() forked"
            );
            // For safety we call setns is a new process to avoid the main process from
            // getting 'poisoned'
            let ns_path = Namespaces::get_proc_path(pid, &ns_type);
            debug!(
                ns_path = ns_path.to_str(),
                "Getting file descriptor for namespace path"
            );
            let fd = match open(&ns_path, OFlag::O_RDONLY, Mode::empty()) {
                Ok(fd) => fd,
                Err(e) => {
                    let data: Result<T, ChildProcessError> =
                        Err(ChildProcessError::Generic(e.to_string()));
                    write_child_process_data(data, addr, ns_type);
                    exit(1);
                }
            };
            debug!(
                ns_path = ns_path.to_str(),
                "Calling setns() on namespace file descriptor"
            );
            if let Err(e) = setns(fd, Namespaces::get_clone_flags(&ns_type)) {
                let data: Result<T, ChildProcessError> =
                    Err(ChildProcessError::Generic(e.to_string()));
                write_child_process_data(data, addr, ns_type);
                exit(1);
            }

            debug!(
                ns_path = ns_path.to_str(),
                "About to run code inside namespace"
            );
            let closure_data = closure(input);
            trace!(
                "Data from child process before sending to parent: {:?}",
                closure_data
            );
            write_child_process_data(closure_data, addr, ns_type);
            debug!("About to gracefully exit child process");
            exit(0);
        }
    };

    if expected_pid != std::process::id() {
        error!(
            "Expecting the PID at this point to be {} but {} is what the current PID is. Panicing!",
            expected_pid,
            std::process::id()
        );
        panic!(); // Panic if we get to this point as the child process to avoid escape
    }

    result
}

#[derive(Default, Debug)]
pub struct Linux {}

impl Linux {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_namespaced_processes(
        &self,
        namespace_types: HashSet<namespaces::Type>,
    ) -> Result<Vec<process::LinuxProcess>, Error> {
        let mut processes: HashMap<Vec<ino_t>, process::LinuxProcess> = HashMap::new();

        for cur_proc in all_processes()? {
            let proc = match cur_proc {
                Ok(p) => p,
                Err(e) => {
                    debug!(
                        "An error was thrown getting a process' data from /proc. Igonring the process: {:?}",
                        e
                    );
                    continue;
                }
            };
            let namespaces = match proc.namespaces() {
                Ok(n) => n,
                Err(e) => {
                    debug!(
                        "An error was thrown getting a process' namespaces. Igonring the process: {:?}",
                        e
                    );
                    continue;
                }
            };
            let mut ino_pair: Vec<ino_t> = vec![];
            for cur_type in &namespace_types {
                ino_pair.push(namespaces::Namespaces::get_namespace_ino(
                    cur_type,
                    &namespaces,
                )?);
            }

            match processes.entry(ino_pair) {
                Entry::Occupied(mut occupied_entry) => {
                    if proc.pid < occupied_entry.get().pid {
                        *occupied_entry.get_mut() = process::LinuxProcess::new(proc.pid)?;
                    }
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(process::LinuxProcess::new(proc.pid)?);
                }
            }
        }

        Ok(processes.into_values().collect())
    }
}

impl Host for Linux {
    #[instrument]
    fn fqdn_hostname(&self) -> Result<OsString, containers::Error> {
        let hostname = gethostname().map_err(|e| containers::Error::Generic(e.to_string()))?;
        Ok(format!("{}.cybertron.lan.", hostname.to_string_lossy()).into())
    }

    #[instrument]
    fn containers(&self) -> Result<Vec<Rc<dyn super::Container>>, containers::Error> {
        let mut arc_processes: Vec<Rc<dyn super::Container>> = vec![];
        for cur_process in self
            .get_namespaced_processes(HashSet::from([namespaces::Type::Net])) // Get processes with unique network namespaces
            .map_err(|e| containers::Error::Generic(e.to_string()))?
        {
            arc_processes.push(Rc::new(cur_process));
        }

        debug!(
            current_pid = std::process::id(),
            "The number of returned containers is {}",
            arc_processes.len()
        );

        Ok(arc_processes)
    }

    #[instrument]
    fn ip_addresses(
        &self,
        addr_type: Option<IpAddrType>,
    ) -> Result<HashSet<IpAddr>, containers::Error> {
        get_ip_addresses(addr_type)
            .map_err(|e| containers::Error::Generic(format!("A Linux errno was returned: {:?}", e)))
    }
}
