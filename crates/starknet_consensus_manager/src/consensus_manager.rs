use std::any::type_name;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use papyrus_consensus::stream_handler::StreamHandler;
use papyrus_consensus::types::ConsensusError;
use papyrus_consensus_orchestrator::sequencer_consensus_context::SequencerConsensusContext;
use papyrus_network::gossipsub_impl::Topic;
use papyrus_network::network_manager::{BroadcastTopicChannels, NetworkManager};
use papyrus_protobuf::consensus::{ConsensusMessage, ProposalPart, StreamMessage};
use starknet_batcher_types::communication::SharedBatcherClient;
use starknet_sequencer_infra::component_definitions::ComponentStarter;
use starknet_sequencer_infra::errors::ComponentError;
use tracing::{error, info};

use crate::config::ConsensusManagerConfig;

// TODO(Dan, Guy): move to config.
pub const BROADCAST_BUFFER_SIZE: usize = 100;
pub const CONSENSUS_PROPOSALS_TOPIC: &str = "consensus_proposals";
pub const CONSENSUS_VOTES_TOPIC: &str = "consensus_votes";
// TODO(guyn): remove this once we have integrated streaming.
pub const NETWORK_TOPIC2: &str = "streamed_consensus_proposals";

#[derive(Clone)]
pub struct ConsensusManager {
    pub config: ConsensusManagerConfig,
    pub batcher_client: SharedBatcherClient,
}

impl ConsensusManager {
    pub fn new(config: ConsensusManagerConfig, batcher_client: SharedBatcherClient) -> Self {
        Self { config, batcher_client }
    }

    pub async fn run(&self) -> Result<(), ConsensusError> {
        let mut network_manager =
            NetworkManager::new(self.config.consensus_config.network_config.clone(), None);

        // TODO(guyn): remove this channel once we have integrated streaming.
        let mut old_proposals_broadcast_channels = network_manager
            .register_broadcast_topic::<ProposalPart>(
                Topic::new(CONSENSUS_PROPOSALS_TOPIC),
                BROADCAST_BUFFER_SIZE,
            )
            .expect("Failed to register broadcast topic");

        let proposals_broadcast_channels = network_manager
            .register_broadcast_topic::<StreamMessage<ProposalPart>>(
                Topic::new(NETWORK_TOPIC2),
                BROADCAST_BUFFER_SIZE,
            )
            .expect("Failed to register broadcast topic");

        let votes_broadcast_channels = network_manager
            .register_broadcast_topic::<ConsensusMessage>(
                Topic::new(CONSENSUS_VOTES_TOPIC),
                BROADCAST_BUFFER_SIZE,
            )
            .expect("Failed to register broadcast topic");

        let BroadcastTopicChannels {
            broadcasted_messages_receiver: inbound_network_receiver,
            broadcast_topic_client: outbound_network_sender,
        } = proposals_broadcast_channels;

        let (outbound_internal_sender, inbound_internal_receiver, mut stream_handler_task_handle) =
            StreamHandler::get_channels(inbound_network_receiver, outbound_network_sender);

        let context = SequencerConsensusContext::new(
            Arc::clone(&self.batcher_client),
            old_proposals_broadcast_channels.broadcast_topic_client.clone(),
            outbound_internal_sender,
            votes_broadcast_channels.broadcast_topic_client.clone(),
            self.config.consensus_config.num_validators,
        );

        let mut network_handle = tokio::task::spawn(network_manager.run());
        let consensus_task = papyrus_consensus::run_consensus(
            context,
            self.config.consensus_config.start_height,
            // TODO(Asmaa): replace with the correct value.
            self.config.consensus_config.start_height,
            self.config.consensus_config.validator_id,
            self.config.consensus_config.consensus_delay,
            self.config.consensus_config.timeouts.clone(),
            votes_broadcast_channels.into(),
            inbound_internal_receiver,
            futures::stream::pending(),
        );

        tokio::select! {
            consensus_result = consensus_task => {
                match consensus_result {
                    Ok(_) => panic!("Consensus task finished unexpectedly"),
                    Err(e) => Err(e),
                }
            },
            network_result = &mut network_handle => {
                panic!("Consensus' network task finished unexpectedly: {:?}", network_result);
            }
            stream_handler_result = &mut stream_handler_task_handle => {
                panic!("Consensus' stream handler task finished unexpectedly: {:?}", stream_handler_result);
            }
            _ = async {
                while let Some(_broadcasted_message) =
                    old_proposals_broadcast_channels.broadcasted_messages_receiver.next().await
                {
                    // TODO(matan): pass receiver to consensus and sender to context.
                }
            } => {
                panic!("Broadcasted messages channel finished unexpectedly");
            }
        }
    }
}

pub fn create_consensus_manager(
    config: ConsensusManagerConfig,
    batcher_client: SharedBatcherClient,
) -> ConsensusManager {
    ConsensusManager::new(config, batcher_client)
}

#[async_trait]
impl ComponentStarter for ConsensusManager {
    async fn start(&mut self) -> Result<(), ComponentError> {
        info!("Starting component {}.", type_name::<Self>());
        self.run().await.map_err(|e| {
            error!("Error running component ConsensusManager: {:?}", e);
            ComponentError::InternalComponentError
        })
    }
}
