use network_relay_rs_core::traffic::TrafficSnapshot;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrafficState {
    #[default]
    Idle,
    Active,
    Unavailable,
}

/// A display window uses cumulative payload counters and the run's monotonic clock.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LiveTraffic {
    pub state: TrafficState,
    pub upload_bytes_per_second: f64,
    pub download_bytes_per_second: f64,
    previous: Option<TrafficSnapshot>,
    window: Option<TrafficSnapshot>,
}

impl LiveTraffic {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn unavailable(&mut self) {
        self.reset();
        self.state = TrafficState::Unavailable;
    }

    pub fn sample(&mut self, next: TrafficSnapshot) {
        let valid = self.previous.is_some_and(|previous| {
            next.elapsed_nanos > previous.elapsed_nanos
                && next.elapsed_nanos - previous.elapsed_nanos <= 3_000_000_000
                && next.upload_bytes >= previous.upload_bytes
                && next.download_bytes >= previous.download_bytes
        });
        if !valid || self.window.is_none() {
            self.reset();
            self.previous = Some(next);
            self.window = Some(next);
            return;
        }
        self.previous = Some(next);
        let window = self.window.unwrap();
        let elapsed = next.elapsed_nanos - window.elapsed_nanos;
        if elapsed < 950_000_000 {
            return;
        }
        let seconds = elapsed as f64 / 1_000_000_000.0;
        self.upload_bytes_per_second = (next.upload_bytes - window.upload_bytes) as f64 / seconds;
        self.download_bytes_per_second = (next.download_bytes - window.download_bytes) as f64 / seconds;
        self.state = if self.upload_bytes_per_second > 0.0 || self.download_bytes_per_second > 0.0 {
            TrafficState::Active
        } else {
            TrafficState::Idle
        };
        self.window = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(upload_bytes: u64, download_bytes: u64, elapsed_nanos: u64) -> TrafficSnapshot {
        TrafficSnapshot { upload_bytes, download_bytes, elapsed_nanos }
    }

    #[test]
    fn averages_a_full_window_using_actual_time_then_becomes_idle() {
        let mut traffic = LiveTraffic::default();
        traffic.sample(snapshot(100, 200, 0));
        traffic.sample(snapshot(500, 1000, 400_000_000));
        assert_eq!(traffic.state, TrafficState::Idle);
        traffic.sample(snapshot(1600, 3200, 1_500_000_000));
        assert_eq!(traffic.upload_bytes_per_second, 1000.0);
        assert_eq!(traffic.download_bytes_per_second, 2000.0);
        assert_eq!(traffic.state, TrafficState::Active);
        traffic.sample(snapshot(1600, 3200, 2_500_000_000));
        assert_eq!(traffic.state, TrafficState::Idle);
        assert_eq!(traffic.upload_bytes_per_second, 0.0);
    }

    #[test]
    fn rollback_long_gap_and_clock_reset_establish_new_baselines() {
        for changed in [
            snapshot(0, 0, 2_000_000_000),
            snapshot(1_000_000, 1_000_000, 5_000_000_001),
            snapshot(100, 100, 1_000_000_000),
        ] {
            let mut traffic = LiveTraffic::default();
            traffic.sample(snapshot(0, 0, 0));
            traffic.sample(snapshot(1000, 2000, 1_000_000_000));
            traffic.sample(changed);
            assert_eq!(traffic.state, TrafficState::Idle);
            assert_eq!(traffic.upload_bytes_per_second, 0.0);
            traffic.sample(snapshot(
                changed.upload_bytes + 100,
                changed.download_bytes + 200,
                changed.elapsed_nanos + 1_000_000_000,
            ));
            assert_eq!(traffic.upload_bytes_per_second, 100.0);
            assert_eq!(traffic.download_bytes_per_second, 200.0);
        }
    }

    #[test]
    fn telemetry_failure_and_new_run_never_reuse_old_rates() {
        let mut traffic = LiveTraffic::default();
        traffic.sample(snapshot(0, 0, 0));
        traffic.sample(snapshot(1000, 2000, 1_000_000_000));
        traffic.unavailable();
        assert_eq!(traffic.state, TrafficState::Unavailable);
        assert_eq!(traffic.download_bytes_per_second, 0.0);
        traffic.sample(snapshot(10_000, 20_000, 5_000_000_000));
        assert_eq!(traffic.state, TrafficState::Idle);
        traffic.reset();
        assert_eq!(traffic, LiveTraffic::default());
    }

    #[test]
    fn one_second_timer_jitter_does_not_delay_display_for_another_second() {
        let mut traffic = LiveTraffic::default();
        traffic.sample(snapshot(0, 0, 0));
        traffic.sample(snapshot(999, 1998, 999_000_000));
        assert_eq!(traffic.state, TrafficState::Active);
        assert_eq!(traffic.upload_bytes_per_second, 1000.0);
        assert_eq!(traffic.download_bytes_per_second, 2000.0);
    }
}
