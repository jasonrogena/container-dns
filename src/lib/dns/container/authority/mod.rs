use hickory_proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
};
use hickory_server::{
    authority::{
        AuthorityObject, LookupControlFlow, LookupObject, LookupOptions, MessageRequest,
        UpdateResult, ZoneType,
    },
    server::RequestInfo,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, instrument};

use crate::dns::container::{
    record_handler::{self, ZoneRecordHandler},
    store::{self, Store},
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
    #[error("Could not receive a message expected from a different thread: {0}")]
    Store(#[from] store::Error),
    #[error("An error was thrown by a record handler: {0}")]
    RecordHandler(#[from] record_handler::Error),
}

pub struct AuthorityRequest {
    pub name: LowerName,
    pub rtype: RecordType,
    pub response_sender: oneshot::Sender<AuthorityResponse>,
}

pub struct AuthorityResponse {
    pub lookup_object: Box<dyn LookupObject>,
}

#[derive(Debug)]
pub struct Authority {
    zone_name: LowerName,
    request_tx: mpsc::Sender<AuthorityRequest>,
}

impl Authority {
    pub fn new() -> Result<(Self, mpsc::Receiver<AuthorityRequest>), Error> {
        let zone_name = ZoneRecordHandler::get_zone_name(Store::host()?)?;
        info!(
            zone = zone_name.to_string(),
            "Initializing the container authority"
        );

        let (tx, rx) = mpsc::channel::<AuthorityRequest>(10);

        Ok((
            Self {
                zone_name,
                request_tx: tx,
            },
            rx,
        ))
    }

    async fn send_request(
        &self,
        name: LowerName,
        rtype: RecordType,
    ) -> Result<Box<dyn LookupObject>, Error> {
        let (tx, rx) = oneshot::channel();
        let request = AuthorityRequest {
            name,
            rtype,
            response_sender: tx,
        };
        self.request_tx.send(request).await?;

        Ok(rx.await?.lookup_object)
    }
}

#[async_trait::async_trait]
impl AuthorityObject for Authority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn can_validate_dnssec(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::Refused)
    }

    fn origin(&self) -> &LowerName {
        &self.zone_name
    }

    #[instrument]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        info!("lookup() called");
        match rtype {
            RecordType::A | RecordType::AAAA | RecordType::SRV | RecordType::NS => {
                match self.send_request(name.clone(), rtype).await {
                    Ok(ok) => LookupControlFlow::Break(Ok(ok)),
                    Err(e) => {
                        error!(
                            "An error was thrown while trying to query a DNS record. Sending back an empty response to the resolver: {:?}",
                            e
                        );
                        LookupControlFlow::Skip
                    }
                }
            }
            _ => LookupControlFlow::Skip,
        }
    }

    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        _last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn ns(&self, lookup_options: LookupOptions) -> LookupControlFlow<Box<dyn LookupObject>> {
        self.lookup(self.origin(), RecordType::NS, lookup_options)
            .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        LookupControlFlow::Skip
    }
}
