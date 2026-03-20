use std::fmt;

use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Histogram, Meter},
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An error occurred while setting up the metrics pipeline: {0}")]
    Setup(String),
}

pub struct Metrics {
    pub zone_size: Gauge<u64>,
    pub zone_refresh_duration: Histogram<f64>,
    pub query_duration: Histogram<f64>,
    pub queries_total: Counter<u64>,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish()
    }
}

impl Metrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            zone_size: meter
                .u64_gauge("dns_zone_size")
                .with_description("Number of unique (record type, name) pairs in the DNS zone")
                .build(),
            zone_refresh_duration: meter
                .f64_histogram("dns_zone_refresh_duration_seconds")
                .with_description("Duration of a DNS zone refresh in seconds")
                .with_unit("s")
                .build(),
            query_duration: meter
                .f64_histogram("dns_query_duration_seconds")
                .with_description("Duration of DNS query handling in seconds")
                .with_unit("s")
                .build(),
            queries_total: meter
                .u64_counter("dns_queries_total")
                .with_description("Total number of DNS queries handled")
                .build(),
        }
    }

    pub fn record_query_success(&self, duration_secs: f64) {
        self.query_duration.record(duration_secs, &[]);
        self.queries_total
            .add(1, &[KeyValue::new("status", "success")]);
    }

    pub fn record_query_failure(&self, duration_secs: f64) {
        self.query_duration.record(duration_secs, &[]);
        self.queries_total
            .add(1, &[KeyValue::new("status", "failure")]);
    }
}

pub fn init_otlp(endpoint: &str) -> Result<SdkMeterProvider, Error> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| Error::Setup(e.to_string()))?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

    Ok(SdkMeterProvider::builder().with_reader(reader).build())
}
