use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use frida_poc::{
    frida_prover::FridaProverBuilder,
    winterfell::{Blake3_256, FriOptions, f128::BaseElement},
};
use hotstuff_rs::{
    events::{
        CommitBlockEvent, InsertBlockEvent, PhaseVoteEvent, ReceiveProposalEvent,
        UpdateHighestPCEvent,
    },
    replica::{Configuration, Replica, ReplicaSpec},
    types::{
        data_types::{BufferSize, ChainID, EpochLength},
        update_sets::{AppStateUpdates, ValidatorSetUpdates, VerifyingKeyBytes},
        validator_set::{SigningKey, ValidatorSet, ValidatorSetState},
    },
};

use crate::{
    frida::FriData,
    frida_app::{FridaApp, FridaTransaction},
    mem_db::MemDB,
    test::{
        logging::{first_seven_base64_chars, log_with_context},
        network::NetworkStub,
    },
};

pub struct Node {
    verifying_key: VerifyingKeyBytes,
    tx_queue: Arc<Mutex<Vec<FridaTransaction>>>,
    replica: Replica<MemDB>,
}

impl Node {
    pub fn new(
        keypair: SigningKey,
        network_stub: NetworkStub,
        lde_blowup_e: i32,
        folding_factor_e: i32,
        max_remainder_degree: usize,
        init_vs_updates: ValidatorSetUpdates,
    ) -> Self {
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
        let prover_builder =
            FridaProverBuilder::<BaseElement, Blake3_256<BaseElement>>::new(options.clone());

        let verifying_key = keypair.verifying_key().to_bytes();
        let tx_queue = Arc::new(Mutex::new(Vec::new()));

        let frida_app = FridaApp::new(tx_queue.clone(), prover_builder);

        // hardcoded values, can be changed later
        let configuration = Configuration::builder()
            .me(keypair)
            .chain_id(ChainID::new(0))
            .block_sync_request_limit(10)
            .block_sync_server_advertise_time(Duration::new(10, 0))
            .block_sync_response_timeout(Duration::new(3, 0))
            .block_sync_blacklist_expiry_time(Duration::new(10, 0))
            .block_sync_trigger_min_view_difference(2)
            .block_sync_trigger_timeout(Duration::new(60, 0))
            .progress_msg_buffer_capacity(BufferSize::new(1024))
            .epoch_length(EpochLength::new(50))
            // `max_view_time` must be **at least** 500 milliseconds, since `NumberApp`'s `produce_block` and
            // `validate_block` each take a minimum of 250 milliseconds to complete.
            .max_view_time(Duration::from_millis(2000))
            .log_events(false)
            .build();

        let kv_store = MemDB::new();
        let mut init_vs = ValidatorSet::new();
        init_vs.apply_updates(&init_vs_updates);
        let init_vs_state = ValidatorSetState::new(init_vs.clone(), init_vs, None, true);

        // Initialize with empty app state
        let init_as_updates = AppStateUpdates::new();
        Replica::initialize(kv_store.clone(), init_as_updates, init_vs_state);

        let replica = ReplicaSpec::builder()
            .app(frida_app)
            .network(network_stub)
            .kv_store(kv_store)
            .configuration(configuration)
            .on_insert_block(insert_block_handler(verifying_key))
            .on_receive_proposal(receive_proposal_handler(verifying_key))
            .on_commit_block(commit_block_handler(verifying_key))
            .on_update_highest_pc(update_highest_pc_handler(verifying_key))
            .on_phase_vote(phase_vote_handler(verifying_key))
            .build()
            .start();

        Self {
            verifying_key,
            tx_queue,
            replica,
        }
    }

    pub fn send_transaction(&self, transactions: Vec<FridaTransaction>) {
        let mut tx_queue = self.tx_queue.lock().unwrap();
        tx_queue.extend(transactions);
    }
}

/// Return a closure that logs out an `InsertBlockEvent` in a human-readable way.
fn insert_block_handler(
    verifying_key: VerifyingKeyBytes,
) -> impl Fn(&InsertBlockEvent) + Send + 'static {
    move |insert_block_event| {
        log_with_context(
            Some(verifying_key),
            &format!(
                "Inserted Block, block hash: {}",
                first_seven_base64_chars(&insert_block_event.block.hash.bytes())
            ),
        );
    }
}

/// Return a closure that logs out an `ReceiveProposalEvent` in a human-readable way.
fn receive_proposal_handler(
    verifying_key: VerifyingKeyBytes,
) -> impl Fn(&ReceiveProposalEvent) + Send + 'static {
    move |receive_proposal_event| {
        let data = receive_proposal_event.proposal.block.data.vec()[1]
            .bytes()
            .to_vec();

        let printable_data = if data.is_empty() {
            String::from("no data")
        } else {
            let fri_data = FriData::from(data);
            format!(
                "FRI data with {} witdh and {} height",
                fri_data.data_list.len(),
                fri_data.data_list[0].len()
            )
        };

        log_with_context(
            Some(verifying_key),
            &format!(
                "Received Proposal, origin: {}, view: {}, block hash: {}, block height: {}, transactions: {}",
                first_seven_base64_chars(&receive_proposal_event.origin.to_bytes()),
                receive_proposal_event.proposal.view,
                first_seven_base64_chars(&receive_proposal_event.proposal.block.hash.bytes()),
                receive_proposal_event.proposal.block.height.clone(),
                printable_data
            ),
        );
    }
}

/// Return a closure that logs out an `CommitBlockEvent` in a human-readable way.
fn commit_block_handler(
    verifying_key: VerifyingKeyBytes,
) -> impl Fn(&CommitBlockEvent) + Send + 'static {
    move |commit_block_event: &CommitBlockEvent| {
        log_with_context(
            Some(verifying_key),
            &format!(
                "Committed Block, block hash: {}",
                first_seven_base64_chars(&commit_block_event.block.bytes())
            ),
        );
    }
}

/// Return a closure that logs out an `UpdateHighestPCEvent` in a human-readable way.
fn update_highest_pc_handler(
    verifying_key: VerifyingKeyBytes,
) -> impl Fn(&UpdateHighestPCEvent) + Send + 'static {
    move |update_highest_pc_event| {
        log_with_context(
            Some(verifying_key),
            &format!(
                "Updated Highest PC, block hash: {}, view: {}, phase: {:?}, no. of signatures: {}",
                first_seven_base64_chars(&update_highest_pc_event.highest_pc.block.bytes()),
                update_highest_pc_event.highest_pc.view,
                update_highest_pc_event.highest_pc.phase,
                update_highest_pc_event
                    .highest_pc
                    .signatures
                    .iter()
                    .filter(|sig| sig.is_some())
                    .count()
            ),
        );
    }
}

/// Return a closure that logs out an `VoteEvent` in a human-readable way.
fn phase_vote_handler(
    verifying_key: VerifyingKeyBytes,
) -> impl Fn(&PhaseVoteEvent) + Send + 'static {
    move |phase_vote_event: &PhaseVoteEvent| {
        log_with_context(
            Some(verifying_key),
            &format!(
                "Phase Voted, block hash: {}, view: {}, phase: {:?}",
                first_seven_base64_chars(&phase_vote_event.vote.block.bytes()),
                phase_vote_event.vote.view,
                phase_vote_event.vote.phase,
            ),
        );
    }
}
