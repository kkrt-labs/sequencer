use std::any::type_name;
use std::net::SocketAddr;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{async_trait, Router, Server};
use hyper::Error;
use starknet_sequencer_infra::component_definitions::ComponentStarter;
use starknet_sequencer_infra::errors::ComponentError;
use tracing::{info, instrument};

use crate::config::MonitoringEndpointConfig;

#[cfg(test)]
#[path = "monitoring_endpoint_test.rs"]
mod monitoring_endpoint_test;

pub(crate) const MONITORING_PREFIX: &str = "monitoring";
pub(crate) const ALIVE: &str = "alive";
pub(crate) const READY: &str = "ready";
pub(crate) const VERSION: &str = "nodeVersion";

pub struct MonitoringEndpoint {
    config: MonitoringEndpointConfig,
    version: &'static str,
}

impl MonitoringEndpoint {
    pub fn new(config: MonitoringEndpointConfig, version: &'static str) -> Self {
        MonitoringEndpoint { config, version }
    }

    #[instrument(
        skip(self),
        fields(
            config = %self.config,
            version = %self.version,
        ),
        level = "debug")]
    pub async fn run(&self) -> Result<(), Error> {
        let MonitoringEndpointConfig { ip, port } = self.config;
        let endpoint_addr = SocketAddr::new(ip, port);

        let app = self.app();
        info!("MonitoringEndpoint running using socket: {}", endpoint_addr);

        Server::bind(&endpoint_addr).serve(app.into_make_service()).await
    }

    fn app(&self) -> Router {
        let version = self.version.to_string();

        Router::new()
            .route(
                format!("/{MONITORING_PREFIX}/{ALIVE}").as_str(),
                get(move || async { StatusCode::OK.to_string() }),
            )
            .route(
                format!("/{MONITORING_PREFIX}/{READY}").as_str(),
                get(move || async { StatusCode::OK.to_string() }),
            )
            .route(
                format!("/{MONITORING_PREFIX}/{VERSION}").as_str(),
                get(move || async { version }),
            )
    }
}

pub fn create_monitoring_endpoint(
    config: MonitoringEndpointConfig,
    version: &'static str,
) -> MonitoringEndpoint {
    MonitoringEndpoint::new(config, version)
}

#[async_trait]
impl ComponentStarter for MonitoringEndpoint {
    async fn start(&mut self) -> Result<(), ComponentError> {
        info!("Starting component {}.", type_name::<Self>());
        self.run().await.map_err(|_| ComponentError::InternalComponentError)
    }
}
