//! Independent connection engine. Local SOCKS listeners are not transparent WFP capture.
pub mod windows;
use proxsep_core::{
    dns::{DnsDecision, DnsMode, DnsPolicy, DnsResolver, FakeIpMap},
    profile::{Action, Chain, Profile, Proxy},
    rules::{Connection, RuleEngine, RuleTrace},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};

const MAX_CONNECTION_EVENTS: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("connection blocked by rule")]
    Blocked,
    #[error("connection timed out")]
    Timeout,
    #[error("profile: {0}")]
    Profile(String),
    #[error("proxy: {0}")]
    Proxy(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub id: u64,
    pub protocol: String,
    pub application: String,
    pub pid: Option<u32>,
    pub target: String,
    pub port: u16,
    pub resolved_ips: Vec<IpAddr>,
    pub destination: Option<SocketAddr>,
    pub interface_id: Option<String>,
    pub bind_ips: Vec<IpAddr>,
    pub rule: String,
    pub rule_trace: Vec<RuleTrace>,
    pub action: String,
    pub state: String,
    pub started_at: SystemTime,
    pub ended_at: Option<SystemTime>,
    pub sent: u64,
    pub received: u64,
    pub error: Option<String>,
}
impl ConnectionEvent {
    pub fn is_active(&self) -> bool {
        matches!(self.state.as_str(), "Connecting" | "Open")
    }

    pub fn duration(&self) -> Option<Duration> {
        self.ended_at
            .unwrap_or_else(SystemTime::now)
            .duration_since(self.started_at)
            .ok()
    }
}
#[derive(Default)]
struct ChainState {
    failed: HashMap<(u32, u32), Instant>,
    sticky: HashMap<(u32, u32), u32>,
}
struct ActiveProfile {
    profile: Profile,
    chains: Arc<Mutex<ChainState>>,
}
pub struct Runtime {
    profile: RwLock<ActiveProfile>,
    events: Arc<Mutex<VecDeque<ConnectionEvent>>>,
    next_id: AtomicU64,
    random: AtomicU64,
    dns: Mutex<DnsResolver>,
}
impl Runtime {
    pub fn new(profile: Profile) -> Arc<Self> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
            ^ (std::process::id() as u64);
        let dns = DnsResolver::new(
            DnsPolicy::new(
                profile.options.resolve.clone(),
                std::env::var("COMPUTERNAME").unwrap_or_default(),
            ),
            FakeIpMap::new(65024).expect("valid fixed capacity"),
            60,
        );
        Arc::new(Self {
            profile: RwLock::new(ActiveProfile {
                profile,
                chains: Arc::new(Mutex::new(ChainState::default())),
            }),
            events: Arc::new(Mutex::new(VecDeque::new())),
            next_id: AtomicU64::new(1),
            random: AtomicU64::new(seed.max(1)),
            dns: Mutex::new(dns),
        })
    }
    pub fn replace_profile(&self, profile: Profile) -> Result<(), RuntimeError> {
        profile
            .validate()
            .map_err(|e| RuntimeError::Profile(e.to_string()))?;
        let mut active = self.profile.write().unwrap();
        self.dns.lock().unwrap().policy = DnsPolicy::new(
            profile.options.resolve.clone(),
            std::env::var("COMPUTERNAME").unwrap_or_default(),
        );
        *active = ActiveProfile {
            profile,
            chains: Arc::new(Mutex::new(ChainState::default())),
        };
        Ok(())
    }
    pub fn events(&self) -> Vec<ConnectionEvent> {
        self.events.lock().unwrap().iter().cloned().collect()
    }
    pub fn active_connections(&self) -> Vec<ConnectionEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.is_active())
            .cloned()
            .collect()
    }
    pub fn clear_events(&self) {
        self.events
            .lock()
            .unwrap()
            .retain(ConnectionEvent::is_active);
    }
    pub fn reset_failures(&self) {
        self.profile.write().unwrap().chains = Arc::new(Mutex::new(ChainState::default()));
    }
    pub fn original_hostname(&self, ip: Ipv4Addr) -> Option<String> {
        self.dns
            .lock()
            .unwrap()
            .mappings
            .reverse(ip)
            .map(str::to_owned)
    }
    pub fn observe_local_dns(&self, available: bool) {
        self.dns.lock().unwrap().policy.observe_local_dns(available);
    }
    pub fn process_dns_packet(&self, packet: &[u8]) -> DnsDecision {
        self.dns.lock().unwrap().handle_datagram(packet)
    }
    fn update(&self, id: u64, f: impl FnOnce(&mut ConnectionEvent)) {
        update_event(&self.events, id, f);
    }
    fn random_index(&self, len: usize) -> usize {
        let mut old = self.random.load(Ordering::Relaxed);
        loop {
            let mut next = old;
            next ^= next << 13;
            next ^= next >> 7;
            next ^= next << 17;
            match self
                .random
                .compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next as usize % len,
                Err(actual) => old = actual,
            }
        }
    }
    pub async fn connect(&self, c: &Connection) -> Result<TrackedTcpStream, RuntimeError> {
        self.connect_recorded(c)
            .await
            .map(|(stream, id)| TrackedTcpStream {
                stream,
                events: Arc::clone(&self.events),
                id,
            })
    }
    async fn connect_recorded(&self, c: &Connection) -> Result<(TcpStream, u64), RuntimeError> {
        let mut c = c.clone();
        let (profile, chain_state, remote) = {
            let active = self.profile.read().unwrap();
            let dns = self.dns.lock().unwrap();
            if let Ok(IpAddr::V4(ip)) = c.target.parse::<IpAddr>()
                && ip.octets()[..2] == [127, 8]
            {
                c.target =
                    dns.mappings.reverse(ip).map(str::to_owned).ok_or_else(|| {
                        RuntimeError::Proxy("unallocated fake DNS address".into())
                    })?;
                c.destination = None;
            }
            let remote = dns
                .policy
                .mode_for_host(&c.target)
                .map_err(|e| RuntimeError::Proxy(e.to_string()))?
                == DnsMode::Remote;
            (active.profile.clone(), Arc::clone(&active.chains), remote)
        };
        profile
            .validate()
            .map_err(|e| RuntimeError::Profile(e.to_string()))?;
        if c.interfaces.is_empty() {
            c.interfaces = windows::interfaces().unwrap_or_default();
        }
        let blocked_without_dns = RuleEngine::new(&profile.rules)
            .decide_without_dns(&c)
            .is_some_and(|d| matches!(d.action, Action::Block));
        if !blocked_without_dns
            && !remote
            && c.target.parse::<IpAddr>().is_err()
            && c.resolved_ips.is_empty()
        {
            let addresses = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((c.target.as_str(), c.port)),
            )
            .await
            .map_err(|_| RuntimeError::Timeout)??;
            c.resolved_ips = addresses.map(|a| a.ip()).collect();
            if c.resolved_ips.is_empty() {
                return Err(RuntimeError::Proxy(
                    "local DNS returned no addresses".into(),
                ));
            }
        }
        let trace = RuleEngine::new(&profile.rules).trace(&c);
        let rule = trace.decision.rule_name.to_owned();
        let interface_id = trace.decision.interface_id.map(str::to_owned);
        c.bind_ips = trace
            .decision
            .interface_id
            .and_then(|id| c.interfaces.get(id))
            .cloned()
            .unwrap_or_default();
        let mut action = trace.decision.action.clone();
        let rule_trace = trace.rules;
        if profile.options.connection_loop_detection
            && matches!(action, Action::Proxy(_) | Action::Chain(_))
            && profile
                .proxies
                .iter()
                .any(|p| p.address.eq_ignore_ascii_case(&c.target) && p.port == c.port)
        {
            if profile.options.connection_loop_resolve {
                action = Action::Direct;
            } else {
                return Err(RuntimeError::Proxy("connection loop detected".into()));
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut events = self.events.lock().unwrap();
            while events.len() >= MAX_CONNECTION_EVENTS {
                let Some(completed) = events.iter().position(|event| !event.is_active()) else {
                    break;
                };
                events.remove(completed);
            }
            events.push_back(ConnectionEvent {
                id,
                protocol: "TCP".into(),
                application: c.application.clone(),
                pid: c.pid,
                target: c.target.clone(),
                port: c.port,
                resolved_ips: c.resolved_ips.clone(),
                destination: c.destination,
                interface_id,
                bind_ips: c.bind_ips.clone(),
                rule,
                rule_trace,
                action: format!("{action:?}"),
                state: "Connecting".into(),
                started_at: SystemTime::now(),
                ended_at: None,
                sent: 0,
                received: 0,
                error: None,
            });
        }
        let _attempt = AttemptGuard { runtime: self, id };
        let result = self.route(&profile, &c, &action, &chain_state).await;
        match result {
            Ok(s) => {
                self.update(id, |e| e.state = "Open".into());
                Ok((s, id))
            }
            Err(error) => {
                self.update(id, |e| {
                    finish_event(e, "Failed", Some(error.to_string()));
                });
                Err(error)
            }
        }
    }
    async fn route(
        &self,
        p: &Profile,
        c: &Connection,
        a: &Action,
        chain_state: &Mutex<ChainState>,
    ) -> Result<TcpStream, RuntimeError> {
        match a {
            Action::Block => Err(RuntimeError::Blocked),
            Action::Direct => direct(c, Duration::from_secs(30)).await,
            Action::Proxy(id) => {
                let proxy = find_proxy(
                    p,
                    id.parse()
                        .map_err(|_| RuntimeError::Profile("invalid proxy ID".into()))?,
                )?;
                self.through(p, c, &[proxy], Duration::from_secs(30)).await
            }
            Action::Chain(id) => {
                let chain = p
                    .chains
                    .iter()
                    .find(|v| v.id.to_string() == *id)
                    .ok_or_else(|| RuntimeError::Profile("missing chain".into()))?;
                let proxies: Vec<_> = chain
                    .proxy_ids
                    .iter()
                    .filter(|id| !chain.disabled_proxy_ids.contains(id))
                    .map(|id| find_proxy(p, *id))
                    .collect::<Result<_, _>>()?;
                if proxies.is_empty() {
                    return Err(RuntimeError::Proxy("chain has no enabled proxies".into()));
                }
                if chain.kind == "simple" {
                    return self
                        .through(
                            p,
                            c,
                            &proxies,
                            Duration::from_secs(chain.redundancy_timeout as u64),
                        )
                        .await;
                }
                self.redundant(p, c, chain, proxies, chain_state).await
            }
        }
    }
    async fn redundant(
        &self,
        p: &Profile,
        c: &Connection,
        chain: &Chain,
        mut proxies: Vec<&Proxy>,
        chain_state: &Mutex<ChainState>,
    ) -> Result<TcpStream, RuntimeError> {
        if chain.kind == "load_balancing" {
            let sticky = if chain.load_balancing_same_proxy_for_pid {
                c.pid.and_then(|pid| {
                    chain_state
                        .lock()
                        .unwrap()
                        .sticky
                        .get(&(chain.id, pid))
                        .copied()
                })
            } else {
                None
            };
            let index = sticky
                .and_then(|id| proxies.iter().position(|p| p.id == id))
                .unwrap_or_else(|| self.random_index(proxies.len()));
            proxies.rotate_left(index);
        }
        let mut last = RuntimeError::Proxy("all proxies failed".into());
        for proxy in &proxies {
            let failed = {
                let state = chain_state.lock().unwrap();
                state.failed.get(&(chain.id, proxy.id)).is_some_and(|at| {
                    !chain.redundancy_recheck
                        || at.elapsed() < Duration::from_secs(chain.redundancy_recheck_time as u64)
                })
            };
            if failed {
                continue;
            }
            match self
                .through(
                    p,
                    c,
                    &[*proxy],
                    Duration::from_secs(chain.redundancy_timeout as u64),
                )
                .await
            {
                Ok(stream) => {
                    let mut state = chain_state.lock().unwrap();
                    state.failed.remove(&(chain.id, proxy.id));
                    if chain.load_balancing_same_proxy_for_pid
                        && let Some(pid) = c.pid
                    {
                        state.sticky.insert((chain.id, pid), proxy.id);
                    }
                    return Ok(stream);
                }
                Err(e) => {
                    chain_state
                        .lock()
                        .unwrap()
                        .failed
                        .insert((chain.id, proxy.id), Instant::now());
                    last = e;
                }
            }
        }
        if chain.redundancy_try_direct {
            direct(c, Duration::from_secs(chain.redundancy_timeout as u64)).await
        } else {
            Err(last)
        }
    }
    async fn through(
        &self,
        p: &Profile,
        c: &Connection,
        proxies: &[&Proxy],
        deadline: Duration,
    ) -> Result<TcpStream, RuntimeError> {
        use proxsep_protocol::{
            http_auth::{AuthConfig, HttpAuthError},
            sspi::{AuthScheme, Credentials},
        };
        tokio::time::timeout(deadline,async {
            let mut preemptive:HashMap<usize,AuthScheme>=HashMap::new();
            for _attempt in 0..3 {
                let first=proxies[0];let mut stream=tcp_connect(&first.address,first.port,c).await?;
                let mut restart=false;
                for(i,proxy)in proxies.iter().enumerate(){
                    if p.password_is_protected(proxy).map_err(|e|RuntimeError::Profile(e.to_string()))?{
                        return Err(RuntimeError::Proxy("encrypted PPX credentials cannot be used as plaintext; decrypt/import first".into()));
                    }
                    let (host,port)=if let Some(next)=proxies.get(i+1){(next.address.as_str(),next.port)}else{(c.target.as_str(),c.port)};
                    let credentials=proxy.username.as_deref().map(|u|(u,proxy.password.as_deref().unwrap_or("")));
                    let host=if i+1==proxies.len()&&!c.resolved_ips.is_empty() {
                        c.resolved_ips.iter().find(|ip|!proxy.protocol.eq_ignore_ascii_case("SOCKS4")||ip.is_ipv4()).ok_or_else(||RuntimeError::Proxy("SOCKS4 requires IPv4".into()))?.to_string()
                    }else if proxy.protocol.eq_ignore_ascii_case("SOCKS4")&&host.parse::<IpAddr>().is_err(){
                        return Err(RuntimeError::Proxy("SOCKS4 cannot resolve a hostname remotely; use SOCKS4A or local DNS".into()));
                    }else{host.into()};
                    match proxy.protocol.to_ascii_uppercase().as_str(){
                        "SOCKS5"=>proxsep_protocol::socks5::negotiate(&mut stream,&host,port,credentials).await.map_err(|e|RuntimeError::Proxy(e.to_string()))?,
                        "SOCKS4"|"SOCKS4A"=>proxsep_protocol::socks4::negotiate(&mut stream,&host,port,proxy.username.as_deref().unwrap_or("")).await.map_err(|e|RuntimeError::Proxy(e.to_string()))?,
                        "HTTPS"=>{
                            let mut auth=AuthConfig::new(&proxy.address);
                            auth.preemptive_scheme=preemptive.get(&i).copied();
                            auth.user_agent=(!proxy.user_agent.is_empty()).then_some(proxy.user_agent.as_str());
                            if let Some((username,password))=credentials {
                                if username.is_empty()&&password.is_empty(){auth.integrated_credentials=Some(Credentials::Default);}
                                else{auth.basic_credentials=Some((username,password));auth.integrated_credentials=Some(Credentials::Explicit{username,password,domain:None});}
                            }
                            match proxsep_protocol::http_auth::negotiate(&mut stream,&host,port,&auth,deadline).await {
                                Ok(())=>{},
                                Err(HttpAuthError::ReconnectRequired{scheme})=>{
                                    if let Some(scheme)=scheme{preemptive.insert(i,scheme);}
                                    restart=true;break;
                                },
                                Err(error)=>return Err(RuntimeError::Proxy(error.to_string())),
                            }
                        },
                        "HTTP"=>return Err(RuntimeError::Proxy("HTTP-only forwarding requires an HTTP request, not an arbitrary TCP tunnel; use HTTPS CONNECT".into())),
                        _=>return Err(RuntimeError::Proxy("unknown proxy protocol".into())),
                    }
                }
                if !restart{return Ok(stream);}
            }
            Err(RuntimeError::Proxy("HTTP proxy repeatedly closed authentication connections".into()))
        }).await.map_err(|_|RuntimeError::Timeout)?
    }
    /// Only sockets redirected by WFP are accepted; ordinary clients cannot
    /// supply their own destination or process identity. Does not load a driver.
    pub async fn start_transparent(
        self: &Arc<Self>,
        address: &str,
    ) -> Result<ListenerHandle, RuntimeError> {
        let bind: SocketAddr = address.parse().map_err(|_| {
            RuntimeError::Profile("numeric transparent listen address required".into())
        })?;
        if !bind.ip().is_loopback() {
            return Err(RuntimeError::Profile(
                "transparent listener restricted to loopback".into(),
            ));
        }
        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let (stop, mut cancel) = watch::channel(false);
        let runtime = Arc::clone(self);
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(256));
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {biased;
                    _=cancel.changed()=>break,
                    Some(_)=clients.join_next(),if !clients.is_empty()=>{},
                    accepted=listener.accept()=>match accepted{Ok((socket,_))=>{if let Ok(permit)=Arc::clone(&permits).try_acquire_owned(){let runtime=Arc::clone(&runtime);let stop=cancel.clone();clients.spawn(async move{let _permit=permit;runtime.serve_transparent(socket,stop).await;});}},Err(_)=>break},
                }
            }
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        });
        Ok(ListenerHandle {
            local_addr,
            stop,
            task: tokio::sync::Mutex::new(Some(task)),
        })
    }
    async fn serve_transparent(&self, client: TcpStream, mut cancel: watch::Receiver<bool>) {
        let Ok(event) = windows::redirect_context(&client) else {
            return;
        };
        if event.protocol() != 6 || event.inbound() || event.process_id() == 0 {
            return;
        }
        let Ok(destination) = windows::parse_event_destination(&event) else {
            return;
        };
        let Ok(application) = windows::decode_application_id(&event) else {
            return;
        };
        let application = windows::native_app_path_to_dos(&application).unwrap_or(application);
        if application.is_empty() {
            return;
        }
        let Ok(records) = windows::redirect_records(&client) else {
            return;
        };
        if records.is_empty() {
            return;
        }
        let mut c = Connection::new(
            application,
            destination.ip().to_string(),
            destination.port(),
        );
        c.pid = Some(event.process_id());
        c.redirect_records = records;
        c.destination = Some(destination);
        let result = tokio::select! {biased;_=cancel.changed()=>return,result=self.connect_recorded(&c)=>result};
        if let Ok((upstream, id)) = result {
            self.relay(client, upstream, id, cancel).await;
        }
    }
    pub async fn start_socks5(
        self: &Arc<Self>,
        address: &str,
        application: String,
    ) -> Result<ListenerHandle, RuntimeError> {
        let bind: SocketAddr = address.parse().map_err(|_| {
            RuntimeError::Profile("listener requires a numeric socket address".into())
        })?;
        if !bind.ip().is_loopback() {
            return Err(RuntimeError::Profile(
                "unauthenticated listener is restricted to loopback".into(),
            ));
        }
        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let (stop, mut stopped) = watch::channel(false);
        let runtime = Arc::clone(self);
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(256));
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {biased;
                    _=stopped.changed()=>break,
                    Some(_)=clients.join_next(),if !clients.is_empty()=>{},
                    accepted=listener.accept()=>match accepted{Ok((socket,_))=>{if let Ok(permit)=Arc::clone(&permits).try_acquire_owned(){let runtime=Arc::clone(&runtime);let app=application.clone();let cancel=stopped.clone();clients.spawn(async move{let _permit=permit;runtime.serve_client(socket,app,cancel).await;});}},Err(_)=>break},
                }
            }
            clients.abort_all();
            while clients.join_next().await.is_some() {}
        });
        Ok(ListenerHandle {
            local_addr,
            stop,
            task: tokio::sync::Mutex::new(Some(task)),
        })
    }
    /// Explicit local DNS endpoint; never changes the host's DNS configuration.
    pub async fn start_dns(
        self: &Arc<Self>,
        address: &str,
        upstream: SocketAddr,
    ) -> Result<ListenerHandle, RuntimeError> {
        let bind: SocketAddr = address
            .parse()
            .map_err(|_| RuntimeError::Profile("numeric DNS listen address required".into()))?;
        if !bind.ip().is_loopback() {
            return Err(RuntimeError::Profile(
                "DNS listener restricted to loopback".into(),
            ));
        }
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        let local_addr = socket.local_addr()?;
        let (stop, mut cancel) = watch::channel(false);
        let runtime = Arc::clone(self);
        let task = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(128));
            let mut jobs = JoinSet::new();
            let mut buffer = vec![0; 65535];
            loop {
                tokio::select! {biased;
                    _=cancel.changed()=>break,
                    Some(_)=jobs.join_next(),if !jobs.is_empty()=>{},
                received=socket.recv_from(&mut buffer)=>match received{Ok((n,peer))=>{if let Ok(permit)=Arc::clone(&permits).try_acquire_owned(){let packet=buffer[..n].to_vec();let socket=Arc::clone(&socket);let runtime=Arc::clone(&runtime);jobs.spawn(async move{let _permit=permit;let response=match runtime.process_dns_packet(&packet){DnsDecision::Answer(answer)=>answer,DnsDecision::Forward{mode,..}=>{if mode==DnsMode::Remote {proxsep_core::dns::error_response(&packet,2)}else{forward_dns(&packet,upstream).await.unwrap_or_else(|_|proxsep_core::dns::error_response(&packet,2))}}};let _=socket.send_to(&response,peer).await;});}},Err(_)=>break},
                }
            }
            jobs.abort_all();
            while jobs.join_next().await.is_some() {}
        });
        Ok(ListenerHandle {
            local_addr,
            stop,
            task: tokio::sync::Mutex::new(Some(task)),
        })
    }
    async fn serve_client(
        &self,
        mut client: TcpStream,
        app: String,
        mut cancel: watch::Receiver<bool>,
    ) {
        let request =
            tokio::time::timeout(Duration::from_secs(15), server_handshake(&mut client)).await;
        let Ok(Ok((host, port))) = request else {
            return;
        };
        let mut c = Connection::new(app, host, port);
        if let Ok((pid, path)) = windows::identify_client(&client) {
            c.pid = Some(pid);
            if c.application.is_empty() {
                c.application = path;
            }
        }
        if c.application.is_empty() {
            c.application = "<unknown client>".into();
        }
        let result = tokio::select! {biased;_=cancel.changed()=>return,result=self.connect_recorded(&c)=>result};
        let (upstream, id) = match result {
            Ok(v) => v,
            Err(e) => {
                let code = if matches!(e, RuntimeError::Blocked) {
                    2
                } else {
                    5
                };
                let _ = client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        };
        let _guard = EventGuard { runtime: self, id };
        let bound = upstream.local_addr().ok();
        let reply = bound
            .map(socks_reply)
            .unwrap_or_else(|| vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        if client.write_all(&reply).await.is_err() {
            self.update(id, |event| finish_event(event, "Closed", None));
            return;
        }
        self.relay(client, upstream, id, cancel).await;
    }
    async fn relay(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        id: u64,
        mut cancel: watch::Receiver<bool>,
    ) {
        let _guard = EventGuard { runtime: self, id };
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let outbound = async {
            let mut buf = [0; 16384];
            loop {
                let n = cr.read(&mut buf).await?;
                if n == 0 {
                    uw.shutdown().await?;
                    return Ok::<_, io::Error>(());
                }
                uw.write_all(&buf[..n]).await?;
                self.update(id, |event| event.sent = event.sent.saturating_add(n as u64));
            }
        };
        let inbound = async {
            let mut buf = [0; 16384];
            loop {
                let n = ur.read(&mut buf).await?;
                if n == 0 {
                    cw.shutdown().await?;
                    return Ok::<_, io::Error>(());
                }
                cw.write_all(&buf[..n]).await?;
                self.update(id, |event| {
                    event.received = event.received.saturating_add(n as u64)
                });
            }
        };
        let result = tokio::select! {biased;_=cancel.changed()=>Ok(()),result=async{tokio::try_join!(outbound,inbound).map(|_|())}=>result};
        self.update(id, |event| {
            finish_event(event, "Closed", result.err().map(|error| error.to_string()));
        });
    }
}
#[derive(Debug)]
pub struct TrackedTcpStream {
    stream: TcpStream,
    events: Arc<Mutex<VecDeque<ConnectionEvent>>>,
    id: u64,
}
impl Deref for TrackedTcpStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}
impl DerefMut for TrackedTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
impl AsyncRead for TrackedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let received = buffer.filled().len().saturating_sub(before) as u64;
            if received != 0 {
                update_event(&self.events, self.id, |event| {
                    event.received = event.received.saturating_add(received)
                });
            }
        }
        result
    }
}
impl AsyncWrite for TrackedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let result = Pin::new(&mut self.stream).poll_write(context, buffer);
        if let Poll::Ready(Ok(sent)) = result
            && sent != 0
        {
            update_event(&self.events, self.id, |event| {
                event.sent = event.sent.saturating_add(sent as u64)
            });
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}
impl Drop for TrackedTcpStream {
    fn drop(&mut self) {
        update_event(&self.events, self.id, |event| {
            if event.is_active() {
                finish_event(event, "Closed", None);
            }
        });
    }
}
pub struct ListenerHandle {
    local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}
impl ListenerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub async fn stop(&self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
    }
}
impl Drop for ListenerHandle {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}
fn find_proxy(p: &Profile, id: u32) -> Result<&Proxy, RuntimeError> {
    p.proxies
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| RuntimeError::Profile("missing proxy".into()))
}

struct EventGuard<'a> {
    runtime: &'a Runtime,
    id: u64,
}
struct AttemptGuard<'a> {
    runtime: &'a Runtime,
    id: u64,
}
impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        self.runtime.update(self.id, |event| {
            if event.state == "Connecting" {
                finish_event(event, "Cancelled", Some("connection cancelled".into()));
            }
        });
    }
}
impl Drop for EventGuard<'_> {
    fn drop(&mut self) {
        self.runtime.update(self.id, |event| {
            if event.state == "Open" {
                finish_event(event, "Closed", None);
            }
        });
    }
}
fn finish_event(event: &mut ConnectionEvent, state: &str, error: Option<String>) {
    event.state = state.into();
    event.ended_at.get_or_insert_with(SystemTime::now);
    if let Some(error) = error {
        event.error = Some(error);
    }
}
fn update_event(
    events: &Mutex<VecDeque<ConnectionEvent>>,
    id: u64,
    update: impl FnOnce(&mut ConnectionEvent),
) {
    let mut events = events.lock().unwrap();
    if let Some(event) = events.iter_mut().find(|event| event.id == id) {
        update(event);
    }
    while events.len() > MAX_CONNECTION_EVENTS {
        let Some(completed) = events.iter().position(|event| !event.is_active()) else {
            break;
        };
        events.remove(completed);
    }
}
async fn tcp_connect(host: &str, port: u16, c: &Connection) -> io::Result<TcpStream> {
    let addresses: Vec<_> = if host == c.target
        && port == c.port
        && let Some(destination) = c.destination
    {
        vec![destination]
    } else if host == c.target && port == c.port && !c.resolved_ips.is_empty() {
        c.resolved_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect()
    } else {
        tokio::net::lookup_host((host, port)).await?.collect()
    };
    let mut last = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no address matching the selected interface",
    );
    for address in addresses {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if !c.bind_ips.is_empty() {
            let Some(ip) = c
                .bind_ips
                .iter()
                .find(|ip| ip.is_ipv4() == address.is_ipv4())
            else {
                continue;
            };
            socket.bind(SocketAddr::new(*ip, 0))?;
        }
        if !c.redirect_records.is_empty() {
            windows::set_redirect_records(&socket, &c.redirect_records)?;
        }
        match socket.connect(address).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}
async fn direct(c: &Connection, deadline: Duration) -> Result<TcpStream, RuntimeError> {
    Ok(
        tokio::time::timeout(deadline, tcp_connect(&c.target, c.port, c))
            .await
            .map_err(|_| RuntimeError::Timeout)??,
    )
}
async fn server_handshake(s: &mut TcpStream) -> io::Result<(String, u16)> {
    if s.read_u8().await? != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let len = s.read_u8().await?;
    let mut methods = vec![0; len as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 255]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no accepted method",
        ));
    }
    s.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    s.read_exact(&mut header).await?;
    if header[..3] != [5, 1, 0] {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only CONNECT supported",
        ));
    }
    let host = match header[3] {
        1 => {
            let mut ip = [0; 4];
            s.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            s.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let len = s.read_u8().await?;
            let mut name = vec![0; len as usize];
            s.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hostname"))?;
            if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid hostname",
                ));
            }
            name
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad address type",
            ));
        }
    };
    let port = s.read_u16().await?;
    if port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "zero port"));
    }
    Ok((host, port))
}
fn socks_reply(address: SocketAddr) -> Vec<u8> {
    let mut b = vec![5, 0, 0];
    match address.ip() {
        IpAddr::V4(a) => {
            b.push(1);
            b.extend(a.octets());
        }
        IpAddr::V6(a) => {
            b.push(4);
            b.extend(a.octets());
        }
    }
    b.extend(address.port().to_be_bytes());
    b
}

async fn forward_dns(packet: &[u8], upstream: SocketAddr) -> io::Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = UdpSocket::bind(if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(upstream).await?;
        socket.send(packet).await?;
        let mut reply = vec![0; 65535];
        let n = socket.recv(&mut reply).await?;
        reply.truncate(n);
        validate_dns_reply(packet, &reply)?;
        if reply[2] & 2 != 0 {
            let mut stream = TcpStream::connect(upstream).await?;
            stream.write_u16(packet.len() as u16).await?;
            stream.write_all(packet).await?;
            let n = stream.read_u16().await? as usize;
            reply.resize(n, 0);
            stream.read_exact(&mut reply).await?;
            validate_dns_reply(packet, &reply)?;
        }
        Ok(reply)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timeout"))?
}
fn validate_dns_reply(query: &[u8], reply: &[u8]) -> io::Result<()> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS upstream returned mismatched response",
        )
    };
    if reply.len() < 12
        || query.len() < 12
        || reply[..2] != query[..2]
        || reply[2] & 0x80 == 0
        || reply[4..6] != [0, 1]
    {
        return Err(bad());
    }
    let q = proxsep_core::dns::parse_query(query).map_err(|_| bad())?;
    let (host, end) = proxsep_core::dns::decode_name(reply, 12).map_err(|_| bad())?;
    if !host.eq_ignore_ascii_case(&q.host)
        || reply.get(end..end + 4)
            != Some(
                [q.qtype.to_be_bytes(), q.qclass.to_be_bytes()]
                    .concat()
                    .as_slice(),
            )
    {
        return Err(bad());
    }
    Ok(())
}
