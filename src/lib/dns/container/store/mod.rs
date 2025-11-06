use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    env::consts,
    rc::Rc,
    time::{self},
};

use hickory_proto::rr::{LowerName, RecordType};
use tokio::{
    sync::{mpsc, oneshot},
    task::LocalSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{Level, debug, error, info, span, warn};

use crate::{
    containers::{Host, IpAddrType, linux::Linux},
    dns::{
        container::{
            authority::{AuthorityRequest, AuthorityResponse},
            record_handler::{
                self, ARecordHandler, RecordHandler, RecordHandlerLookupObject, SrvRecordHandler,
                ZoneRecordHandler,
            },
        },
        settings::Settings,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The Operating System {0} is currently not supported")]
    UnsupportedOs(String),
    #[error(
        "An error occurred while working with the system for identifying isoated processes: {0}"
    )]
    Containers(#[from] crate::containers::Error),
    #[error("Could not determine the hostname")]
    Hostname(),
    #[error("A Hickory protocol error was thrown: {0}")]
    HickoryProto(#[from] hickory_proto::ProtoError),
    #[error("Could not find process with PID {0}")]
    ProcessNotFound(u32),
    #[error("Could not send a request to the authority store: {0}")]
    RequestSendError(#[from] mpsc::error::SendError<AuthorityRequest>),
    #[error("Could not receive a message expected from a different thread: {0}")]
    OneshotRecvError(#[from] oneshot::error::RecvError),
    #[error("An error was thrown by a record handler: {0}")]
    RecordHandler(#[from] record_handler::Error),
}

type RecordHandlers = HashMap<(RecordType, LowerName), Rc<dyn RecordHandler>>;

pub struct Store {
    host: Rc<dyn Host>,
    record_handlers: RecordHandlers,
    config: Settings,
    request_rx: mpsc::Receiver<AuthorityRequest>,
    zone_name: LowerName,
}

impl Store {
    pub async fn start(
        local_set: LocalSet,
        config: Settings,
        shutdown_token: CancellationToken,
        rx: mpsc::Receiver<AuthorityRequest>,
    ) {
        let mut refresh_interval = tokio::time::interval(config.refresh_interval);
        local_set.run_until(async move {
            let mut store = match Store::new(config, rx) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "An error was thrown while initializing the zone store: {:?}",
                        e
                    );
                    return;
                }
            };

            loop {
                tokio::select! {
                    _ = refresh_interval.tick() => {
                        store.update_containers();
                    },
                    res = store.handle_next_request() => {
                        if let Err(e) = res {
                            error!("An error was thrown as the store attempted to handle a request: {:?}", e);
                        }
                    },
                };
                if shutdown_token.is_cancelled() {
                    info!("Thread updating container authority terminated");
                    return;
                }
            }
        }).await;
    }

    fn new(config: Settings, request_rx: mpsc::Receiver<AuthorityRequest>) -> Result<Self, Error> {
        let host: Rc<dyn Host> = Self::host()?;
        let zone_name = ZoneRecordHandler::get_zone_name(host.clone())?;
        Ok(Self {
            host,
            record_handlers: HashMap::new(),
            config,
            request_rx,
            zone_name,
        })
    }

    pub fn host() -> Result<Rc<dyn Host>, Error> {
        let host: Rc<dyn Host> = match consts::OS {
            "linux" => Rc::new(Linux::new()),
            unsupported_os => return Err(Error::UnsupportedOs(unsupported_os.to_string())),
        };

        Ok(host)
    }

    async fn handle_next_request(&mut self) -> Result<(), Error> {
        if let Some(request) = self.request_rx.recv().await {
            let pair = (request.rtype, request.name);
            let lookup_object = match self.record_handlers.get(&pair) {
                Some(handler) => handler.lookup_object(),
                None => Box::new(RecordHandlerLookupObject::default()),
            };

            if request
                .response_sender
                .send(AuthorityResponse { lookup_object })
                .is_err()
            {
                error!(
                    rtype = pair.0.to_string(),
                    name = pair.1.to_string(),
                    "Could not send back a response for request"
                );
            }
        }

        Ok(())
    }

    fn update_containers(&mut self) {
        info!("update_containers() started");
        let timing = time::Instant::now();
        let mut record_handlers: HashMap<(RecordType, LowerName), Box<dyn RecordHandler>> =
            HashMap::new();

        let mut zone_record_handler = ZoneRecordHandler::new(
            self.zone_name.clone(),
            self.host.clone(),
            false,
            self.config.clone(),
        );
        if let Err(e) = zone_record_handler.update_records() {
            warn!(
                "An error was thrown while trying to get NS names for container. Defaulting to an empty list of names: {:?}",
                e
            );
        }
        record_handlers.insert(
            (RecordType::NS, self.zone_name.clone()),
            Box::new(zone_record_handler),
        );

        let containers = match self.host.containers() {
            Ok(ok) => ok,
            Err(e) => {
                warn!(
                    "Could not get the host's containers due to an error: {:?}",
                    e
                );
                vec![]
            }
        };
        info!("update_containers() gotten {} containers", containers.len());

        let host_fqdn_hostname = match self.host.fqdn_hostname() {
            Ok(name) => name,
            Err(e) => {
                warn!("An error was thrown trying to get the hostname: {:?}", e);
                return;
            }
        };
        for (container_index, cur_proc) in containers.iter().enumerate() {
            let span = span!(
                Level::INFO,
                "get_container_records",
                index = format!("{}/{}", container_index + 1, containers.len())
            );
            let _enter = span.enter();
            let listening_services = match SrvRecordHandler::get_listening_services(
                cur_proc.clone(),
            ) {
                Ok(ok) => ok,
                Err(e) => {
                    warn!(
                        "An error was thrown while trying to get listening services for a container: {:?}",
                        e
                    );
                    HashSet::new()
                }
            };
            debug!(
                "Current process has {} listening services",
                listening_services.len()
            );
            for cur_service in listening_services {
                let srv_names = match SrvRecordHandler::get_service_names(
                    &cur_service,
                    cur_proc.clone(),
                    &host_fqdn_hostname,
                ) {
                    Ok(ok) => ok,
                    Err(e) => {
                        warn!(
                            service = cur_service.to_string(),
                            "An error was thrown while trying to get SVC names for container. Defaulting to an empty list of names: {:?}",
                            e
                        );
                        HashSet::new()
                    }
                };
                for cur_name in srv_names {
                    match record_handlers.entry((RecordType::SRV, cur_name.clone())) {
                        Entry::Occupied(mut occupied_entry) => {
                            if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone())
                            {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = cur_name.to_string(),
                                    "An error was thrown while attempting to append SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                        }
                        Entry::Vacant(vacant_entry) => {
                            let mut handler = SrvRecordHandler::new(
                                HashSet::from([cur_name.clone()]),
                                cur_service.clone(),
                                self.config.clone(),
                                vec![cur_proc.clone()],
                                containers.clone(),
                                host_fqdn_hostname.clone(),
                            );
                            if let Err(e) = handler.update_records() {
                                warn!(
                                    service = cur_service.to_string(),
                                    service_name = cur_name.to_string(),
                                    "An error was thrown while attempting to create SRV DNS names for container: {:?}",
                                    e
                                );
                            }
                            vacant_entry.insert(Box::new(handler));
                        }
                    }
                }
            }

            let a_names = match ARecordHandler::get_names(
                cur_proc.clone(),
                &containers,
                &host_fqdn_hostname,
            ) {
                Ok(ok) => ok,
                Err(e) => {
                    warn!(
                        "An error was thrown while trying to get A names for container. Defaulting to an empty list of names: {:?}",
                        e
                    );
                    HashSet::new()
                }
            };

            for cur_name in a_names {
                match record_handlers.entry((RecordType::A, cur_name.clone())) {
                    Entry::Occupied(mut occupied_entry) => {
                        if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone()) {
                            warn!(
                                a_name = cur_name.to_string(),
                                "An error was thrown while attempting to add A DNS names for container: {:?}",
                                e
                            );
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        let mut handler = ARecordHandler::new(
                            HashSet::from([cur_name.clone()]),
                            self.config.clone(),
                            Some(IpAddrType::V4),
                            vec![cur_proc.clone()],
                        );
                        if let Err(e) = handler.update_records() {
                            warn!(
                                a_name = cur_name.to_string(),
                                "An error was thrown while attempting to add A DNS names for container: {:?}",
                                e
                            );
                        }
                        vacant_entry.insert(Box::new(handler));
                    }
                }
                match record_handlers.entry((RecordType::AAAA, cur_name.clone())) {
                    Entry::Occupied(mut occupied_entry) => {
                        if let Err(e) = occupied_entry.get_mut().add_container(cur_proc.clone()) {
                            warn!(
                                aaaa_name = cur_name.to_string(),
                                "An error was thrown while attempting to add AAAA DNS names for container: {:?}",
                                e
                            );
                        }
                    }
                    Entry::Vacant(vacant_entry) => {
                        let mut handler = ARecordHandler::new(
                            HashSet::from([cur_name.clone()]),
                            self.config.clone(),
                            Some(IpAddrType::V6),
                            vec![cur_proc.clone()],
                        );
                        if let Err(e) = handler.update_records() {
                            warn!(
                                aaaa_name = cur_name.to_string(),
                                "An error was thrown while attempting to add AAAA DNS names for container: {:?}",
                                e
                            );
                        }
                        vacant_entry.insert(Box::new(handler));
                    }
                }
            }
        }

        self.record_handlers
            .retain(|k, _| record_handlers.contains_key(k));
        for (k, v) in record_handlers.drain() {
            info!(
                record_type = k.0.to_string(),
                name = k.1.to_string(),
                "Updating DNS record"
            );
            match self.record_handlers.entry(k) {
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.insert(v.into());
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(v.into());
                }
            }
        }

        info!(
            "Done updating DNS records in authority in {:?}",
            timing.elapsed()
        );
    }
}
