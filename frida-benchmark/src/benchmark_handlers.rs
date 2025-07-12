use hotstuff_rs::events::{
    CollectPCEvent, PhaseVoteEvent, ProposeEvent, ReceivePhaseVoteEvent, ReceiveProposalEvent,
    StartViewEvent,
};

pub struct BenchmarkHandler;

pub(crate) type HandlerPtr<T> = Box<dyn Fn(&T) + Send>;

impl BenchmarkHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn start_view(&self) -> HandlerPtr<StartViewEvent> {
        todo!()
    }

    pub fn propose(&self) -> HandlerPtr<ProposeEvent> {
        todo!()
    }

    pub fn receive_proposal(&self) -> HandlerPtr<ReceiveProposalEvent> {
        todo!()
    }

    pub fn phase_vote(&self) -> HandlerPtr<PhaseVoteEvent> {
        todo!()
    }

    pub fn receive_phase_vote(&self) -> HandlerPtr<ReceivePhaseVoteEvent> {
        todo!()
    }

    pub fn collect_pc(&self) -> HandlerPtr<CollectPCEvent> {
        todo!()
    }
}
