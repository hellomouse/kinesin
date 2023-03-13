use crossbeam_channel::{Sender, Receiver};
use parking_lot::Mutex;

// TODO: rewrite this, and message broker
pub trait MessageTarget<MessageType, Target: MessageHandler<MessageType>> {
    fn _messaging_defer(&self);
    fn _messaging_get_target(&self) -> &Mutex<Target>;
    fn _messaging_get_channel(&self) -> (Sender<MessageType>, Receiver<MessageType>);
    fn _messaging_default_process_limit(&self) -> usize {
        64
    }

    fn inform(&self, message: MessageType) -> bool {
        let (s, _) = self._messaging_get_channel();
        s.send(message).unwrap();
        self.process_messages()
    }

    fn process_messages(&self) -> bool {
        self.process_messages_limit(self._messaging_default_process_limit())
    }

    fn process_messages_limit(&self, limit: usize) -> bool {
        let (_, r) = self._messaging_get_channel();
        let mut processed: usize = 0;
        let target = self._messaging_get_target();
        loop {
            let maybe_guard = target.try_lock();
            if maybe_guard.is_none() {
                return false;
            }

            let mut guard = maybe_guard.unwrap();
            loop {
                let m = r.try_recv();
                if let Ok(message) = m {
                    guard.handle_message(message);
                    processed += 1;
                    if processed >= limit {
                        // schedule for later
                        self._messaging_defer();
                        return false;
                    }
                } else {
                    break;
                }
            }

            // ensure channel is empty (prevent races)
            drop(guard);
            if !r.is_empty() {
                continue;
            } else {
                return true;
            }
        }
    }
}

pub trait MessageHandler<T> {
    fn handle_message(&mut self, message: T);
}
