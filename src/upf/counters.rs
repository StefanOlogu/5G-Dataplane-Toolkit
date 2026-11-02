
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug,Default)]
pub struct Counters{
    pub ul_forwarded : AtomicU64,
    pub ul_echo_replies: AtomicU64,
    pub ul_malformed : AtomicU64,
    pub ul_not_gpdu : AtomicU64,
    pub ul_unknown_teid: AtomicU64,
    pub dl_forwarded : AtomicU64,
    pub dl_not_ipv4 : AtomicU64,
    pub dl_unknown_ue: AtomicU64,
    pub dl_encap_error: AtomicU64,
    pub send_errors : AtomicU64,
    pub recv_errors : AtomicU64,
}

#[derive(Debug,Default,Clone,Copy,PartialEq,Eq)]
pub struct CounterSnapshot{
    pub ul_forwarded : u64,
    pub ul_echo_replies: u64,
    pub ul_malformed : u64,
    pub ul_not_gpdu : u64,
    pub ul_unknown_teid: u64,
    pub dl_forwarded : u64,
    pub dl_not_ipv4 : u64,
    pub dl_unknown_ue: u64,
    pub dl_encap_error: u64,
    pub send_errors : u64,
    pub recv_errors : u64,
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        let r = |c: &AtomicU64| c.load(Ordering::Relaxed);
        CounterSnapshot {
            ul_forwarded: r(&self.ul_forwarded),
            ul_echo_replies: r(&self.ul_echo_replies),
            ul_malformed: r(&self.ul_malformed),
            ul_not_gpdu: r(&self.ul_not_gpdu),
            ul_unknown_teid: r(&self.ul_unknown_teid),
            dl_forwarded: r(&self.dl_forwarded),
            dl_not_ipv4: r(&self.dl_not_ipv4),
            dl_unknown_ue: r(&self.dl_unknown_ue),
            dl_encap_error: r(&self.dl_encap_error),
            send_errors: r(&self.send_errors),
            recv_errors: r(&self.recv_errors),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reflects_increments() {
        let c = Counters::default();
        inc(&c.ul_forwarded);
        inc(&c.ul_forwarded);
        inc(&c.dl_unknown_ue);

        assert_eq!(
            c.snapshot(),
            CounterSnapshot { ul_forwarded: 2, dl_unknown_ue: 1, ..Default::default() }
        );
    }
}