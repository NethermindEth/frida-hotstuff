use hotstuff_rs::events::StartViewEvent;

pub struct BenchmarkHandler;

pub(crate) type HandlerPtr<T> = Box<dyn Fn(&T) + Send>;

impl BenchmarkHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn start_view(&self) -> HandlerPtr<StartViewEvent> {
        todo!()
    }
}
