use std::collections::{HashMap, hash_map::Entry};

use hickory_proto::rr::{LowerName, RecordType};
use hickory_server::authority::LookupObject;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use crate::dns::container::record_handler::{self, RecordHandlerLookupObject};

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
    RequestSendError(#[from] mpsc::error::SendError<StoreRequest>),
    #[error("Could not receive a message expected from a different thread: {0}")]
    OneshotRecvError(#[from] oneshot::error::RecvError),
    #[error("An error was thrown by a record handler: {0}")]
    RecordHandler(#[from] record_handler::Error),
}

pub enum StoreRequest {
    QUERY(StoreQueryRequest),
    UPDATE(StoreUpdateRequest),
}

pub struct StoreQueryRequest {
    pub name: LowerName,
    pub rtype: RecordType,
    pub response_sender: oneshot::Sender<StoreResponse>,
}

pub struct StoreUpdateRequest {
    pub lookup_objects: RecordHandlerLookupObjects,
}

pub enum StoreResponse {
    ANSWER(StoreAnswerResponse),
}

pub struct StoreAnswerResponse {
    pub lookup_object: Box<dyn LookupObject>,
}

pub type RecordHandlerLookupObjects = HashMap<(RecordType, LowerName), RecordHandlerLookupObject>;

pub struct Store {
    lookup_objects: RecordHandlerLookupObjects,
    request_rx: mpsc::Receiver<StoreRequest>,
    shutdown_token: CancellationToken,
}

impl Store {
    pub async fn start(&mut self) {
        loop {
            if let Err(e) = self.handle_next_request().await {
                error!(
                    "An error was thrown as the store attempted to handle a request: {:?}",
                    e
                );
            }
            if self.shutdown_token.is_cancelled() {
                info!("Thread updating container authority terminated");
                return;
            }
        }
    }

    pub fn new(
        shutdown_token: CancellationToken,
        request_rx: mpsc::Receiver<StoreRequest>,
    ) -> Self {
        Self {
            lookup_objects: HashMap::new(),
            request_rx,
            shutdown_token,
        }
    }

    async fn handle_next_request(&mut self) -> Result<(), Error> {
        match self.request_rx.recv().await {
            Some(req) => match req {
                StoreRequest::QUERY(query_req) => self.handle_query_request(query_req).await,
                StoreRequest::UPDATE(update_req) => self.handle_update_request(update_req),
            },
            None => Ok(()),
        }
    }

    async fn handle_query_request(&self, request: StoreQueryRequest) -> Result<(), Error> {
        let pair = (request.rtype, request.name);
        let lookup_object: Box<dyn LookupObject> = match self.lookup_objects.get(&pair) {
            Some(obj) => Box::new(obj.clone()),
            None => Box::new(RecordHandlerLookupObject::default()),
        };

        if request
            .response_sender
            .send(StoreResponse::ANSWER(StoreAnswerResponse { lookup_object }))
            .is_err()
        {
            error!(
                rtype = pair.0.to_string(),
                name = pair.1.to_string(),
                "Could not send back a response for request"
            );
        }

        Ok(())
    }

    fn handle_update_request(&mut self, request: StoreUpdateRequest) -> Result<(), Error> {
        self.lookup_objects
            .retain(|k, _| request.lookup_objects.contains_key(k));
        for (k, v) in request.lookup_objects {
            debug!(
                record_type = k.0.to_string(),
                name = k.1.to_string(),
                "Updating DNS record"
            );
            match self.lookup_objects.entry(k) {
                Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.insert(v);
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(v);
                }
            }
        }

        Ok(())
    }
}
