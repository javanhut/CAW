//! Deadlines, and the single `timerfd` that arms the nearest one.
//!
//! Everything below the daemon is sans-IO and so cannot read a clock: a state
//! machine that wants a retransmit in a second says so with an action, and
//! this is where that becomes a kernel timer. One `timerfd` serves all of
//! them, armed for whichever deadline is closest, because the reactor needs
//! exactly one descriptor to wake on and not one per timer.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::time::{
    Itimerspec, Nsecs, Secs, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec,
    timerfd_create, timerfd_settime,
};

/// Pending deadlines, keyed by whatever the caller uses to tell them apart.
///
/// A `Vec` scanned linearly rather than a heap: there are single digits of
/// timers at any moment — a scan timeout, a handshake retransmit, a DHCP
/// renewal — and arming replaces by key, which a heap makes harder than the
/// scan it saves.
pub struct Timers<K> {
    entries: Vec<Entry<K>>,
}

struct Entry<K> {
    key: K,
    at: Instant,
}

impl<K: Copy + PartialEq> Default for Timers<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Copy + PartialEq> Timers<K> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Arm `key` to fire `delay` from `now`, replacing any earlier arming.
    ///
    /// Replacing rather than adding is what the sans-IO layers expect: a
    /// state machine that re-arms its retransmit timer means "not that one,
    /// this one".
    pub fn arm(&mut self, key: K, delay: Duration, now: Instant) {
        let at = now + delay;
        match self.entries.iter_mut().find(|e| e.key == key) {
            Some(entry) => entry.at = at,
            None => self.entries.push(Entry { key, at }),
        }
    }

    pub fn cancel(&mut self, key: K) {
        self.entries.retain(|e| e.key != key);
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.at).min()
    }

    /// Remove and return everything due at `now`, soonest first.
    pub fn expired(&mut self, now: Instant) -> Vec<K> {
        let mut due: Vec<&Entry<K>> = self.entries.iter().filter(|e| e.at <= now).collect();
        due.sort_by_key(|e| e.at);
        let keys: Vec<K> = due.into_iter().map(|e| e.key).collect();
        self.entries.retain(|e| e.at > now);
        keys
    }
}

/// The reactor's clock, as a pollable descriptor.
pub struct TimerFd {
    fd: OwnedFd,
}

impl TimerFd {
    pub fn new() -> rustix::io::Result<Self> {
        let fd = timerfd_create(
            // Monotonic, so a step of the wall clock cannot postpone a
            // handshake retransmit by an hour or fire every timer at once.
            TimerfdClockId::Monotonic,
            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
        )?;
        Ok(Self { fd })
    }

    /// Fire once after `delay`, or disarm when there is nothing pending.
    pub fn arm(&self, delay: Option<Duration>) -> rustix::io::Result<()> {
        // A zero `it_value` disarms the timer rather than firing immediately,
        // so a deadline already in the past is armed one nanosecond out. It
        // fires on the next trip round the loop, which is what the caller
        // meant.
        let value = match delay {
            None => Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            Some(d) if d.is_zero() => Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            },
            Some(d) => Timespec {
                tv_sec: d.as_secs() as Secs,
                tv_nsec: Nsecs::from(d.subsec_nanos()),
            },
        };
        timerfd_settime(
            &self.fd,
            TimerfdTimerFlags::empty(),
            &Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: value,
            },
        )?;
        Ok(())
    }

    /// Clear the expiry count so `poll` stops reporting the descriptor ready.
    pub fn drain(&self) {
        let mut buf = [0u8; 8];
        let _ = rustix::io::read(&self.fd, &mut buf);
    }
}

impl AsFd for TimerFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Key {
        Scan,
        Handshake,
        Dhcp,
    }

    /// A fixed base rather than repeated `Instant::now()` calls: the wheel is
    /// pure, and the test says so by never letting real time in.
    fn base() -> Instant {
        Instant::now()
    }

    #[test]
    fn nearest_deadline_wins() {
        let now = base();
        let mut timers = Timers::new();
        timers.arm(Key::Scan, Duration::from_secs(10), now);
        timers.arm(Key::Handshake, Duration::from_secs(1), now);
        timers.arm(Key::Dhcp, Duration::from_secs(5), now);

        assert_eq!(timers.next_deadline(), Some(now + Duration::from_secs(1)));
    }

    #[test]
    fn arming_twice_replaces_rather_than_duplicates() {
        let now = base();
        let mut timers = Timers::new();
        timers.arm(Key::Handshake, Duration::from_secs(1), now);
        timers.arm(Key::Handshake, Duration::from_secs(30), now);

        assert_eq!(timers.next_deadline(), Some(now + Duration::from_secs(30)));
        assert!(timers.expired(now + Duration::from_secs(60)).len() == 1);
    }

    #[test]
    fn expiry_returns_the_due_ones_in_order_and_keeps_the_rest() {
        let now = base();
        let mut timers = Timers::new();
        timers.arm(Key::Scan, Duration::from_secs(3), now);
        timers.arm(Key::Handshake, Duration::from_secs(1), now);
        timers.arm(Key::Dhcp, Duration::from_secs(60), now);

        let due = timers.expired(now + Duration::from_secs(5));
        assert_eq!(due, vec![Key::Handshake, Key::Scan]);
        assert_eq!(timers.next_deadline(), Some(now + Duration::from_secs(60)));
    }

    #[test]
    fn cancelling_disarms_the_wheel_entirely_when_it_was_the_last() {
        let now = base();
        let mut timers = Timers::new();
        timers.arm(Key::Scan, Duration::from_secs(3), now);
        timers.cancel(Key::Scan);

        assert_eq!(timers.next_deadline(), None);
        assert!(timers.expired(now + Duration::from_secs(600)).is_empty());
    }

    #[test]
    fn a_timerfd_armed_in_the_past_still_fires() {
        let timerfd = TimerFd::new().unwrap();
        timerfd.arm(Some(Duration::ZERO)).unwrap();

        let mut fds = [rustix::event::PollFd::new(
            &timerfd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        assert_eq!(rustix::event::poll(&mut fds, Some(&timeout)).unwrap(), 1);
        timerfd.drain();
    }
}
