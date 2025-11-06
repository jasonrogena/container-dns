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
    record_handler::{self},
    store::{self, StoreQueryRequest, StoreRequest, StoreResponse},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    #[error("Could not receive a message expected from a different thread: {0}")]
    Store(#[from] store::Error),
    #[error("An error was thrown by a record handler: {0}")]
    RecordHandler(#[from] record_handler::Error),
}

#[derive(Debug)]
pub struct Authority {
    zone_name: LowerName,
    store_request_tx: mpsc::Sender<StoreRequest>,
}

impl Authority {
    pub fn new(zone_name: LowerName, store_request_tx: mpsc::Sender<StoreRequest>) -> Self {
        info!(
            zone = zone_name.to_string(),
            "Initializing the container authority"
        );

        Self {
            zone_name,
            store_request_tx,
        }
    }

    async fn send_request(
        &self,
        name: LowerName,
        rtype: RecordType,
    ) -> Result<Box<dyn LookupObject>, Error> {
        let (tx, rx) = oneshot::channel();
        let request = StoreRequest::QUERY(StoreQueryRequest {
            name,
            rtype,
            response_sender: tx,
        });
        self.store_request_tx.send(request).await?;

        match rx.await? {
            StoreResponse::ANSWER(ans) => Ok(ans.lookup_object),
        }
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
