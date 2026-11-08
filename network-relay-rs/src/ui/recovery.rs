//! GUI-only recovery. The headless controller and protocol core are unchanged.
use crate::controller::{Controller, Status};
use std::time::{Duration, Instant};

pub(super) struct Recovery {
    pending: Option<Instant>,
    probe_retry: Option<Instant>,
    wanted: bool,
    delay: Duration,
    connected_since: Option<Instant>,
    suppressed: bool,
}

impl Default for Recovery {
    fn default() -> Self {
        Self {
            pending: None,
            probe_retry: None,
            wanted: false,
            delay: Duration::from_secs(1),
            connected_since: None,
            suppressed: false,
        }
    }
}
impl Recovery {
    pub fn cancel(&mut self) {
        *self = Self::default();
        self.suppressed = true;
    }
    pub fn status(&self, controller: &Controller) -> Status {
        if self.pending.is_some() { Status::Reconnecting } else { controller.status.clone() }
    }
    pub fn connect(&mut self, controller: &mut Controller) {
        self.cancel();
        self.suppressed = false;
        controller.connect();
        self.wanted = controller.status.is_active();
    }
    pub fn disconnect(&mut self, controller: &mut Controller) {
        self.cancel();
        controller.disconnect();
    }
    pub fn settings_applied(&mut self, controller: &Controller, allow_reconnect: bool) {
        if !allow_reconnect || !controller.is_configured() {
            self.cancel();
        } else if self.pending.is_some() {
            // A right-hand choice applies as soon as the old listener is gone.
            self.pending = Some(Instant::now());
            self.delay = Duration::from_secs(1);
        }
    }
    pub fn poll(&mut self, controller: &mut Controller, now: Instant, network_changed: bool) {
        controller.poll();
        if self.suppressed {
            return;
        }
        if self.pending.is_none() {
            if controller.status.is_active() {
                self.wanted = true;
            } else {
                self.wanted = false;
                self.connected_since = None;
            }
        }
        if network_changed && self.wanted {
            self.probe_retry = None;
            self.delay = Duration::from_secs(1);
            self.connected_since = None;
            controller.detail = "Network changed; opening a fresh relay connection".into();
            self.restart(controller, now, Duration::from_secs(1));
        } else if self.pending.is_none() {
            match controller.status {
                Status::Connected => {
                    self.probe_retry = None;
                    self.connected_since.get_or_insert(now);
                }
                Status::Reconnecting
                    if self.wanted && !controller.detail.contains("relay refused the request with HTTP ") =>
                {
                    // A reset of just the admission stream must not kill healthy
                    // SOCKS flows if the core can renew it on the same session.
                    let deadline = self.probe_retry.get_or_insert(now + Duration::from_secs(2));
                    if now < *deadline {
                        return;
                    }
                    self.probe_retry = None;
                    if self
                        .connected_since
                        .take()
                        .is_some_and(|since| now.duration_since(since) >= Duration::from_secs(30))
                    {
                        self.delay = Duration::from_secs(1);
                    }
                    let delay = self.delay;
                    self.delay = (self.delay * 2).min(Duration::from_secs(30));
                    self.restart(controller, now, delay);
                }
                _ => self.probe_retry = None,
            }
        }
        if self.pending.is_some_and(|deadline| now >= deadline) && controller.status == Status::Stopped {
            self.pending = None;
            controller.connect();
            self.wanted = controller.status.is_active();
        }
    }
    fn restart(&mut self, controller: &mut Controller, now: Instant, delay: Duration) {
        if self.pending.is_none() {
            controller.disconnect();
        }
        self.pending = Some(self.pending.map_or(now + delay, |previous| previous.min(now + delay)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Configuration, Server, Transport};
    use std::{
        net::{TcpListener, TcpStream},
        thread,
    };

    fn setup() -> (Controller, TcpListener) {
        let relay = TcpListener::bind("127.0.0.1:0").unwrap();
        relay.set_nonblocking(true).unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        drop(proxy);
        let server = Server {
            domain: format!("relay.test:{}", relay.local_addr().unwrap().port()),
            server_ip: "127.0.0.1".into(),
            username: "test".into(),
            password: "test-password".into(),
            transport: Transport::H2,
            ..Server::default()
        };
        let config =
            Configuration { selected_server_id: Some(server.id), servers: vec![server], port, ..Default::default() };
        (Controller::with_configuration(config, None, None), relay)
    }
    fn accept(recovery: &mut Recovery, controller: &mut Controller, relay: &TcpListener) -> TcpStream {
        let started = Instant::now();
        loop {
            recovery.poll(controller, Instant::now(), false);
            match relay.accept() {
                Ok((socket, _)) => return socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("accept failed: {error}"),
            }
            assert!(started.elapsed() < Duration::from_secs(5), "no fresh socket: {:?}", controller.status);
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn a_network_change_opens_a_new_socket_after_releasing_the_listener() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        recovery.poll(&mut controller, Instant::now(), true);
        assert_eq!(recovery.status(&controller), Status::Reconnecting);
        let _fresh = accept(&mut recovery, &mut controller, &relay);
        let proxy = ("127.0.0.1", controller.config.port);
        assert_eq!(TcpListener::bind(proxy).unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
        recovery.disconnect(&mut controller);
        controller.stop();
        let _released = TcpListener::bind(proxy).unwrap();
    }
    #[test]
    fn retry_status_rebuilds_the_gui_worker_but_manual_disconnect_cancels_it() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        controller.status = Status::Reconnecting;
        recovery.poll(&mut controller, Instant::now(), false);
        let _fresh = accept(&mut recovery, &mut controller, &relay);
        recovery.poll(&mut controller, Instant::now(), true);
        recovery.disconnect(&mut controller);
        // Network changes during teardown must not undo the user's choice.
        recovery.poll(&mut controller, Instant::now() + Duration::from_secs(60), true);
        controller.stop();
        recovery.poll(&mut controller, Instant::now() + Duration::from_secs(120), true);
        assert_eq!(controller.status, Status::Stopped);
        assert!(relay.accept().is_err());
    }
    #[test]
    fn right_hand_choices_replace_a_pending_retry_without_waiting_for_its_backoff() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        recovery.delay = Duration::from_secs(30);
        controller.status = Status::Reconnecting;
        let now = Instant::now();
        recovery.poll(&mut controller, now, false);
        recovery.poll(&mut controller, now + Duration::from_secs(2), false);
        assert!(recovery.pending.is_some());
        let mut config = controller.config.clone();
        config.servers[0].transport = Transport::Http1;
        controller.apply_choice(config).unwrap();
        recovery.settings_applied(&controller, true);
        let _fresh = accept(&mut recovery, &mut controller, &relay);
        assert_eq!(controller.config.selected_server().unwrap().transport, Transport::Http1);
        recovery.disconnect(&mut controller);
        controller.stop();
    }
    #[test]
    fn repeated_network_events_do_not_postpone_a_queued_connection() {
        let (mut controller, _relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let now = Instant::now();
        recovery.poll(&mut controller, now, true);
        let deadline = recovery.pending.unwrap();
        recovery.poll(&mut controller, now + Duration::from_millis(500), true);
        assert_eq!(recovery.pending.unwrap(), deadline);
        recovery.disconnect(&mut controller);
        controller.stop();
    }
    #[test]
    fn gateway_replies_do_not_discard_active_flows_without_a_path_change() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        controller.status = Status::Reconnecting;
        controller.detail = "relay refused the request with HTTP 503 Service Unavailable".into();
        recovery.poll(&mut controller, Instant::now(), false);
        assert!(recovery.pending.is_none(), "a live gateway response must keep existing flows");
        assert!(relay.accept().is_err());
        recovery.poll(&mut controller, Instant::now(), true);
        let _fresh = accept(&mut recovery, &mut controller, &relay);
        recovery.disconnect(&mut controller);
        controller.stop();
    }
    #[test]
    fn a_recovered_probe_keeps_healthy_connections() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        let now = Instant::now();
        controller.status = Status::Reconnecting;
        recovery.poll(&mut controller, now, false);
        assert!(recovery.probe_retry.is_some());
        assert!(recovery.pending.is_none());
        controller.status = Status::Connected;
        recovery.poll(&mut controller, now + Duration::from_secs(1), false);
        recovery.poll(&mut controller, now + Duration::from_secs(5), false);
        assert!(recovery.probe_retry.is_none());
        assert_eq!(recovery.status(&controller), Status::Connected);
        assert!(relay.accept().is_err(), "a recovered stream must not replace the connection");
        recovery.disconnect(&mut controller);
        controller.stop();
    }
    #[test]
    fn repeated_probe_failures_have_a_fixed_recovery_deadline() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        let now = Instant::now();
        controller.status = Status::Reconnecting;
        recovery.poll(&mut controller, now, false);
        let deadline = recovery.probe_retry.unwrap();
        recovery.poll(&mut controller, now + Duration::from_secs(1), false);
        assert_eq!(recovery.probe_retry, Some(deadline));
        recovery.poll(&mut controller, deadline, false);
        assert!(recovery.probe_retry.is_none());
        assert!(recovery.pending.is_some(), "a stalled probe must still trigger full recovery");
        recovery.disconnect(&mut controller);
        controller.stop();
    }
    #[test]
    fn terminal_failure_cancels_the_probe_recovery_window() {
        let (mut controller, relay) = setup();
        let mut recovery = Recovery::default();
        recovery.connect(&mut controller);
        let _old = accept(&mut recovery, &mut controller, &relay);
        controller.status = Status::Reconnecting;
        recovery.poll(&mut controller, Instant::now(), false);
        controller.stop();
        controller.status = Status::Failed("certificate rejected".into());
        recovery.poll(&mut controller, Instant::now() + Duration::from_secs(10), true);
        assert!(matches!(controller.status, Status::Failed(_)));
        assert!(recovery.probe_retry.is_none() && recovery.pending.is_none());
        assert!(relay.accept().is_err());
    }
}
