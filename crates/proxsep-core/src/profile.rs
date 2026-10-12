use std::collections::HashSet;
use xmltree::{Element, XMLNode};

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("invalid Proxifier profile: {0}")]
    Decode(String),
    #[error("cannot serialize Proxifier profile: {0}")]
    Encode(String),
}
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub version: u32,
    pub platform: String,
    pub options: Options,
    pub proxies: Vec<Proxy>,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
    /// In-memory credential provenance; never serialized into PPX.
    pub credential_state: CredentialState,
    /// Original document preserves opaque extensions and product metadata.
    pub original_xml: Option<String>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 102,
            platform: "Windows".into(),
            options: Options::default(),
            proxies: vec![],
            chains: vec![],
            rules: vec![Rule {
                name: "Default".into(),
                ..Rule::default()
            }],
            credential_state: CredentialState::Plaintext,
            original_xml: None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    Plaintext,
    Opaque,
    AccountUnlocked,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub resolve: ResolveOptions,
    pub encryption_mode: String,
    pub connection_loop_detection: bool,
    pub connection_loop_resolve: bool,
    pub udp_mode: String,
    pub leak_prevention: bool,
    pub process_other_users: bool,
    pub process_services: bool,
    pub handle_direct_connections: bool,
    pub http_proxies_support: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            resolve: ResolveOptions::default(),
            encryption_mode: "disabled".into(),
            connection_loop_detection: true,
            connection_loop_resolve: true,
            udp_mode: "mode_bypass".into(),
            leak_prevention: false,
            process_other_users: false,
            process_services: false,
            handle_direct_connections: false,
            http_proxies_support: false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOptions {
    pub auto_mode_detection: bool,
    pub via_proxy: bool,
    pub block_non_a_types: bool,
    pub exclusion_list: String,
    pub exclusion_only_from_list: bool,
    pub dns_udp_mode: u8,
}
impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            auto_mode_detection: true,
            via_proxy: false,
            block_non_a_types: false,
            exclusion_list: "%ComputerName%; localhost; *.local".into(),
            exclusion_only_from_list: false,
            dns_udp_mode: 0,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub id: u32,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub label: String,
    pub user_agent: String,
    pub options: u32,
}
impl Default for Proxy {
    fn default() -> Self {
        Self {
            id: 1,
            protocol: "SOCKS5".into(),
            address: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            label: String::new(),
            user_agent: String::new(),
            options: 0,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub id: u32,
    pub name: String,
    pub proxy_ids: Vec<u32>,
    pub kind: String,
    pub disabled_proxy_ids: Vec<u32>,
    pub redundancy_timeout: u32,
    pub redundancy_try_direct: bool,
    pub redundancy_recheck: bool,
    pub redundancy_recheck_time: u32,
    pub load_balancing_same_proxy_for_pid: bool,
}
impl Default for Chain {
    fn default() -> Self {
        Self {
            id: 2,
            name: "Chain".into(),
            proxy_ids: vec![],
            kind: "simple".into(),
            disabled_proxy_ids: vec![],
            redundancy_timeout: 10,
            redundancy_try_direct: false,
            redundancy_recheck: true,
            redundancy_recheck_time: 60,
            load_balancing_same_proxy_for_pid: false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Action {
    #[default]
    Direct,
    Block,
    Proxy(String),
    Chain(String),
}
#[derive(Debug, Clone)]
pub struct Rule {
    pub enabled: bool,
    pub name: String,
    pub applications: String,
    pub targets: String,
    pub ports: String,
    pub action: Action,
    pub interface_id: String,
    pub skip_if_interface_down: bool,
    /// The source node belongs to this rule, not its editable name or position.
    /// Preserve opaque attributes/children when cloning, renaming, or reordering.
    pub original_element: Option<Element>,
}
// Source formatting and opaque metadata are not routing semantics.
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.name == other.name
            && self.applications == other.applications
            && self.targets == other.targets
            && self.ports == other.ports
            && self.action == other.action
            && self.interface_id == other.interface_id
            && self.skip_if_interface_down == other.skip_if_interface_down
    }
}
impl Eq for Rule {}
impl Default for Rule {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "Rule".into(),
            applications: String::new(),
            targets: String::new(),
            ports: String::new(),
            action: Action::Direct,
            interface_id: String::new(),
            skip_if_interface_down: false,
            original_element: None,
        }
    }
}

fn invalid(s: impl Into<String>) -> ProfileError {
    ProfileError::Decode(s.into())
}
fn text(e: &Element, n: &str) -> String {
    e.get_child(n)
        .and_then(Element::get_text)
        .map(|s| s.into_owned())
        .unwrap_or_default()
}
fn attr<'a>(e: &'a Element, n: &str, d: &'a str) -> &'a str {
    e.attributes.get(n).map(String::as_str).unwrap_or(d)
}
fn number<T: std::str::FromStr>(s: &str, n: &str) -> Result<T, ProfileError> {
    s.parse().map_err(|_| invalid(format!("invalid {n}: {s}")))
}
fn boolean(s: &str) -> Result<bool, ProfileError> {
    match s {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(invalid(format!("invalid boolean: {s}"))),
    }
}
fn flag(e: &Element, n: &str, d: bool) -> Result<bool, ProfileError> {
    e.get_child(n)
        .map(|e| boolean(attr(e, "enabled", if d { "true" } else { "false" })))
        .unwrap_or(Ok(d))
}
fn elements<'a>(e: &'a Element, list: &str, item: &'a str) -> impl Iterator<Item = &'a Element> {
    e.get_child(list)
        .into_iter()
        .flat_map(|e| e.children.iter())
        .filter_map(XMLNode::as_element)
        .filter(move |e| e.name == item)
}
fn num_child(e: &Element, n: &str, d: u32) -> Result<u32, ProfileError> {
    let s = text(e, n);
    if s.is_empty() { Ok(d) } else { number(&s, n) }
}
fn bool_child(e: &Element, n: &str, d: bool) -> Result<bool, ProfileError> {
    let s = text(e, n);
    if s.is_empty() { Ok(d) } else { boolean(&s) }
}

impl Profile {
    pub fn from_xml_for_current_user(xml: &str) -> Result<Self, ProfileError> {
        let mut profile = Self::from_xml(xml)?;
        if profile.options.encryption_mode == "account" {
            profile.unlock_account_credentials()?;
        }
        Ok(profile)
    }

    pub fn from_xml(xml: &str) -> Result<Self, ProfileError> {
        if xml.len() > 5 * 1024 * 1024 {
            return Err(invalid("profile exceeds 5 MiB"));
        }
        let root = Element::parse(xml.as_bytes()).map_err(|e| invalid(e.to_string()))?;
        if root.name != "ProxifierProfile" {
            return Err(invalid("expected ProxifierProfile root"));
        }
        let mut p = Self {
            // Native parser leaves a missing version at zero and rejects it.
            version: number(attr(&root, "version", ""), "version")?,
            platform: attr(&root, "platform", "Windows").into(),
            original_xml: Some(xml.into()),
            ..Self::default()
        };
        p.rules.clear();
        if let Some(o) = root.get_child("Options") {
            let opt = &mut p.options;
            if let Some(r) = o.get_child("Resolve") {
                opt.resolve.auto_mode_detection = flag(r, "AutoModeDetection", true)?;
                opt.resolve.via_proxy = flag(r, "ViaProxy", false)?;
                opt.resolve.block_non_a_types = flag(r, "BlockNonATypes", false)?;
                if let Some(e) = r.get_child("ExclusionList") {
                    opt.resolve.exclusion_list =
                        e.get_text().map(|s| s.into_owned()).unwrap_or_default();
                    opt.resolve.exclusion_only_from_list =
                        boolean(attr(e, "OnlyFromListMode", "false"))?;
                }
                opt.resolve.dns_udp_mode = u8::try_from(num_child(r, "DnsUdpMode", 0)?)
                    .map_err(|_| invalid("invalid DnsUdpMode"))?;
            }
            if let Some(e) = o.get_child("Encryption") {
                opt.encryption_mode = match attr(e, "mode", "disabled") {
                    "none" => "disabled",
                    other => other,
                }
                .into();
                p.credential_state = if matches!(opt.encryption_mode.as_str(), "disabled" | "none")
                {
                    CredentialState::Plaintext
                } else {
                    CredentialState::Opaque
                };
            }
            if let Some(e) = o.get_child("ConnectionLoopDetection") {
                opt.connection_loop_detection = boolean(attr(e, "enabled", "true"))?;
                opt.connection_loop_resolve = boolean(attr(e, "resolve", "true"))?;
            }
            if let Some(e) = o.get_child("Udp") {
                opt.udp_mode = attr(e, "mode", "mode_bypass").into();
            }
            opt.leak_prevention = flag(o, "LeakPreventionMode", false)?;
            opt.process_other_users = flag(o, "ProcessOtherUsers", false)?;
            opt.process_services = flag(o, "ProcessServices", false)?;
            opt.handle_direct_connections = flag(o, "HandleDirectConnections", false)?;
            opt.http_proxies_support = flag(o, "HttpProxiesSupport", false)?;
        }
        for e in elements(&root, "ProxyList", "Proxy") {
            let mut proxy = Proxy {
                id: number(attr(e, "id", "0"), "proxy ID")?,
                protocol: attr(e, "type", "SOCKS5").into(),
                address: text(e, "Address"),
                port: number(&text(e, "Port"), "proxy port")?,
                label: text(e, "Label"),
                user_agent: text(e, "UserAgent"),
                options: num_child(e, "Options", 0)?,
                ..Proxy::default()
            };
            if let Some(a) = e.get_child("Authentication") {
                if boolean(attr(a, "enabled", "false"))? {
                    proxy.username = Some(text(a, "Username"));
                    proxy.password = Some(text(a, "Password"));
                }
            } else if e.get_child("Username").is_some() {
                proxy.username = Some(text(e, "Username"));
                proxy.password = Some(text(e, "Password"));
            }
            p.proxies.push(proxy);
        }
        for e in elements(&root, "ChainList", "Chain") {
            let mut c = Chain {
                id: number(attr(e, "id", "0"), "chain ID")?,
                name: text(e, "Name"),
                kind: attr(e, "type", "simple").into(),
                ..Chain::default()
            };
            for e in e
                .children
                .iter()
                .filter_map(XMLNode::as_element)
                .filter(|e| e.name == "Proxy")
            {
                let id = number(e.get_text().as_deref().unwrap_or(""), "chain proxy ID")?;
                c.proxy_ids.push(id);
                if !boolean(attr(e, "enabled", "true"))? {
                    c.disabled_proxy_ids.push(id);
                }
            }
            c.redundancy_timeout = num_child(e, "RedundancyTimeout", 10)?;
            c.redundancy_try_direct = bool_child(e, "RedundancyTryDirect", false)?;
            c.redundancy_recheck = bool_child(e, "RedundancyRecheck", true)?;
            c.redundancy_recheck_time = num_child(e, "RedundancyRecheckTime", 60)?;
            c.load_balancing_same_proxy_for_pid =
                bool_child(e, "LoadBalancingSameProxyForPid", false)?;
            p.chains.push(c);
        }
        for e in elements(&root, "RuleList", "Rule") {
            let a = e
                .get_child("Action")
                .ok_or_else(|| invalid("rule action missing"))?;
            let id = a.get_text().map(|s| s.into_owned()).unwrap_or_default();
            let action = match attr(a, "type", "Direct") {
                "Direct" => Action::Direct,
                "Block" => Action::Block,
                "Proxy" => Action::Proxy(id),
                "Chain" => Action::Chain(id),
                s => return Err(invalid(format!("unknown action: {s}"))),
            };
            p.rules.push(Rule {
                enabled: boolean(attr(e, "enabled", "true"))?,
                name: text(e, "Name"),
                applications: text(e, "Applications"),
                targets: text(e, "Targets"),
                ports: text(e, "Ports"),
                action,
                interface_id: attr(e, "interfaceId", "").into(),
                skip_if_interface_down: boolean(attr(e, "skipIfInterfaceDown", "false"))?,
                original_element: Some(e.clone()),
            });
        }
        p.validate()?;
        Ok(p)
    }
    pub fn validate(&self) -> Result<(), ProfileError> {
        if !(100..=102).contains(&self.version) {
            return Err(invalid("profile version must be between 100 and 102"));
        }
        let mut ids = HashSet::new();
        for p in &self.proxies {
            if p.id == 0 || !ids.insert(p.id) {
                return Err(invalid("duplicate/zero proxy ID"));
            }
            if p.port == 0 || p.address.trim().is_empty() {
                return Err(invalid("empty proxy address/zero port"));
            }
            if !["SOCKS4", "SOCKS4A", "SOCKS5", "HTTPS", "HTTP"]
                .iter()
                .any(|s| p.protocol.eq_ignore_ascii_case(s))
            {
                return Err(invalid("unknown proxy protocol"));
            }
        }
        let mut chains = HashSet::new();
        for c in &self.chains {
            if c.id == 0 || !chains.insert(c.id) {
                return Err(invalid("duplicate/zero chain ID"));
            }
            if c.name.trim().is_empty()
                || !["simple", "redundancy", "load_balancing"].contains(&c.kind.as_str())
            {
                return Err(invalid("invalid chain name/type"));
            }
            if c.redundancy_timeout == 0 || c.redundancy_recheck_time == 0 {
                return Err(invalid("zero chain timeout"));
            }
            // Native parser 0x140070772 checks this upper bound for redundancy.
            if c.kind == "redundancy" && c.redundancy_timeout > 9999 {
                return Err(invalid("redundancy timeout must be between 1 and 9999"));
            }
            if c.proxy_ids.iter().any(|id| !ids.contains(id)) {
                return Err(invalid("chain refers to missing proxy"));
            }
            if c.kind == "simple" {
                for id in c
                    .proxy_ids
                    .iter()
                    .filter(|id| !c.disabled_proxy_ids.contains(id))
                    .rev()
                    .skip(1)
                {
                    if self
                        .proxies
                        .iter()
                        .any(|p| p.id == *id && p.protocol.eq_ignore_ascii_case("HTTP"))
                    {
                        return Err(invalid("HTTP proxy must be last in chain"));
                    }
                }
            }
        }
        for r in &self.rules {
            if r.name.trim().is_empty() {
                return Err(invalid("rule name missing"));
            }
            match &r.action {
                Action::Proxy(s)
                    if !number::<u32>(s, "action ID").is_ok_and(|n| ids.contains(&n)) =>
                {
                    return Err(invalid("rule refers to missing proxy"));
                }
                Action::Chain(s)
                    if !number::<u32>(s, "action ID").is_ok_and(|n| chains.contains(&n)) =>
                {
                    return Err(invalid("rule refers to missing chain"));
                }
                _ => {}
            }
            crate::rules::validate_ports(&r.ports).map_err(invalid)?;
        }
        Ok(())
    }
    /// Track the original carrier across a mode edit: changing only the mode
    /// does not decrypt a password. A replacement value in disabled mode is an
    /// explicit plaintext edit, not an automatic conversion.
    pub fn password_is_protected(&self, proxy: &Proxy) -> Result<bool, ProfileError> {
        let Some(password) = proxy.password.as_deref().filter(|p| !p.is_empty()) else {
            return Ok(false);
        };
        if self.credential_state == CredentialState::AccountUnlocked {
            return Ok(false);
        }
        if !matches!(self.options.encryption_mode.as_str(), "disabled" | "none") {
            return Ok(true);
        }
        let Some(source) = self.original_xml.as_deref() else {
            return Ok(false);
        };
        let original = Self::from_xml(source)?;
        Ok(!matches!(
            original.options.encryption_mode.as_str(),
            "disabled" | "none"
        ) && original
            .proxies
            .iter()
            .any(|old| old.password.as_deref() == Some(password)))
    }
    pub fn enable_account_protection(&mut self) -> Result<(), ProfileError> {
        for proxy in &self.proxies {
            if self.password_is_protected(proxy)? {
                return Err(ProfileError::Encode(
                    "opaque credentials must be unlocked or replaced before enabling account protection"
                        .into(),
                ));
            }
        }
        self.options.encryption_mode = "account".into();
        self.credential_state = CredentialState::AccountUnlocked;
        Ok(())
    }
    pub fn unlock_account_credentials(&mut self) -> Result<(), ProfileError> {
        if self.options.encryption_mode != "account" {
            return Err(ProfileError::Decode(
                "profile is not protected for the current Windows account".into(),
            ));
        }
        if self.credential_state == CredentialState::AccountUnlocked {
            return Ok(());
        }
        let source = self
            .original_xml
            .as_deref()
            .ok_or_else(|| invalid("account-protected profile has no source document"))?;
        let root = Element::parse(source.as_bytes()).map_err(|e| invalid(e.to_string()))?;
        let hash = root
            .get_child("Options")
            .and_then(|options| options.get_child("Encryption"))
            .map(|encryption| text(encryption, "Hash"))
            .unwrap_or_default();
        let check = crate::credentials::unprotect_account(&hash).map_err(invalid)?;
        if check != "A" {
            return Err(invalid("account protection validation failed"));
        }
        let mut decrypted = Vec::with_capacity(self.proxies.len());
        for proxy in &self.proxies {
            decrypted.push(
                proxy
                    .password
                    .as_deref()
                    .map(crate::credentials::unprotect_account)
                    .transpose()
                    .map_err(invalid)?,
            );
        }
        for (proxy, password) in self.proxies.iter_mut().zip(decrypted) {
            proxy.password = password;
        }
        self.credential_state = CredentialState::AccountUnlocked;
        Ok(())
    }
    pub fn to_xml(&self) -> Result<String, ProfileError> {
        self.validate()?;
        let account_unlocked = self.options.encryption_mode == "account"
            && self.credential_state == CredentialState::AccountUnlocked;
        if self.credential_state == CredentialState::AccountUnlocked
            && !matches!(
                self.options.encryption_mode.as_str(),
                "account" | "disabled" | "none"
            )
        {
            return Err(ProfileError::Encode(
                "unlocked account credentials cannot be relabeled as another protected mode".into(),
            ));
        }
        let original = self
            .original_xml
            .as_deref()
            .map(Self::from_xml)
            .transpose()?;
        if matches!(self.options.encryption_mode.as_str(), "disabled" | "none")
            && let Some(source) = &original
            && !matches!(source.options.encryption_mode.as_str(), "disabled" | "none")
        {
            for proxy in &self.proxies {
                if let Some(password) = proxy.password.as_deref().filter(|p| !p.is_empty())
                    && source
                        .proxies
                        .iter()
                        .any(|old| old.password.as_deref() == Some(password))
                {
                    return Err(ProfileError::Encode("changing encryption mode does not decrypt opaque passwords; replace them explicitly before plaintext export".into()));
                }
            }
        }
        if !matches!(self.options.encryption_mode.as_str(), "disabled" | "none")
            && !account_unlocked
        {
            if matches!(self.options.encryption_mode.as_str(), "account" | "master")
                && !original
                    .as_ref()
                    .is_some_and(|p| p.options.encryption_mode == self.options.encryption_mode)
            {
                return Err(ProfileError::Encode("creating account/master protection requires the protected Hash backend; existing protected profiles may be preserved".into()));
            }
            for proxy in self.proxies.iter().filter(|p| p.username.is_some()) {
                if !original.as_ref().is_some_and(|p| {
                    p.options.encryption_mode == self.options.encryption_mode
                        && p.proxies
                            .iter()
                            .any(|old| old.id == proxy.id && old.password == proxy.password)
                }) {
                    return Err(ProfileError::Encode("editing protected credentials requires a compatible encryption backend; select disabled mode for plaintext export".into()));
                }
            }
        }
        let mut root = match &self.original_xml {
            Some(s) => Element::parse(s.as_bytes()).map_err(|e| invalid(e.to_string()))?,
            None => Element::new("ProxifierProfile"),
        };
        set_attr(&mut root, "version", self.version);
        set_attr(&mut root, "platform", &self.platform);
        root.attributes
            .entry("product_id".into())
            .or_insert("0".into());
        root.attributes
            .entry("product_minver".into())
            .or_insert("400".into());
        let o = child(&mut root, "Options");
        let p = &self.options;
        let r = child(o, "Resolve");
        for (n, v) in [
            ("AutoModeDetection", p.resolve.auto_mode_detection),
            ("ViaProxy", p.resolve.via_proxy),
            ("BlockNonATypes", p.resolve.block_non_a_types),
        ] {
            set_flag(r, n, v);
        }
        set_text(r, "ExclusionList", &p.resolve.exclusion_list);
        set_attr(
            child(r, "ExclusionList"),
            "OnlyFromListMode",
            p.resolve.exclusion_only_from_list,
        );
        set_text(r, "DnsUdpMode", p.resolve.dns_udp_mode);
        let encryption = child(o, "Encryption");
        set_attr(encryption, "mode", &p.encryption_mode);
        if account_unlocked {
            let hash = crate::credentials::protect_account("A").map_err(ProfileError::Encode)?;
            set_text(encryption, "Hash", hash);
        } else if matches!(p.encryption_mode.as_str(), "disabled" | "none") {
            encryption.children.retain(|node| {
                !node
                    .as_element()
                    .is_some_and(|element| element.name == "Hash")
            });
        }
        let e = child(o, "ConnectionLoopDetection");
        set_attr(e, "enabled", p.connection_loop_detection);
        set_attr(e, "resolve", p.connection_loop_resolve);
        set_attr(child(o, "Udp"), "mode", &p.udp_mode);
        for (n, v) in [
            ("LeakPreventionMode", p.leak_prevention),
            ("ProcessOtherUsers", p.process_other_users),
            ("ProcessServices", p.process_services),
            ("HandleDirectConnections", p.handle_direct_connections),
            ("HttpProxiesSupport", p.http_proxies_support),
        ] {
            set_flag(o, n, v);
        }
        let serialized_passwords = self
            .proxies
            .iter()
            .map(|proxy| {
                if account_unlocked {
                    proxy
                        .password
                        .as_deref()
                        .map(crate::credentials::protect_account)
                        .transpose()
                        .map_err(ProfileError::Encode)
                } else {
                    Ok(proxy.password.clone())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        rebuild(
            &mut root,
            "ProxyList",
            "Proxy",
            self.proxies.iter().map(|p| p.id.to_string()).collect(),
            |e, i| {
                let p = &self.proxies[i];
                set_attr(e, "id", p.id);
                set_attr(e, "type", &p.protocol);
                set_text(e, "Address", &p.address);
                set_text(e, "Port", p.port);
                set_text(e, "Label", &p.label);
                set_text(e, "UserAgent", &p.user_agent);
                set_text(e, "Options", p.options);
                let a = child(e, "Authentication");
                set_attr(a, "enabled", p.username.is_some());
                if let Some(u) = &p.username {
                    set_text(a, "Username", u);
                    set_text(
                        a,
                        "Password",
                        serialized_passwords[i].as_deref().unwrap_or(""),
                    );
                }
            },
        );
        rebuild(
            &mut root,
            "ChainList",
            "Chain",
            self.chains.iter().map(|c| c.id.to_string()).collect(),
            |e, i| {
                let c = &self.chains[i];
                set_attr(e, "id", c.id);
                set_attr(e, "type", &c.kind);
                set_text(e, "Name", &c.name);
                e.children
                    .retain(|n| !n.as_element().is_some_and(|e| e.name == "Proxy"));
                for id in &c.proxy_ids {
                    let mut p = Element::new("Proxy");
                    set_attr(&mut p, "enabled", !c.disabled_proxy_ids.contains(id));
                    p.children.push(XMLNode::Text(id.to_string()));
                    e.children.push(XMLNode::Element(p));
                }
                for (n, v) in [
                    ("RedundancyTimeout", c.redundancy_timeout.to_string()),
                    ("RedundancyTryDirect", c.redundancy_try_direct.to_string()),
                    ("RedundancyRecheck", c.redundancy_recheck.to_string()),
                    (
                        "RedundancyRecheckTime",
                        c.redundancy_recheck_time.to_string(),
                    ),
                    (
                        "LoadBalancingSameProxyForPid",
                        c.load_balancing_same_proxy_for_pid.to_string(),
                    ),
                ] {
                    set_text(e, n, v);
                }
            },
        );
        rebuild(
            &mut root,
            "RuleList",
            "Rule",
            self.rules.iter().map(|r| r.name.clone()).collect(),
            |e, i| {
                let r = &self.rules[i];
                *e = r
                    .original_element
                    .clone()
                    .unwrap_or_else(|| Element::new("Rule"));
                set_attr(e, "enabled", r.enabled);
                if r.interface_id.is_empty() {
                    e.attributes.remove("interfaceId");
                } else {
                    set_attr(e, "interfaceId", &r.interface_id);
                }
                set_attr(e, "skipIfInterfaceDown", r.skip_if_interface_down);
                set_text(e, "Name", &r.name);
                set_text(e, "Applications", &r.applications);
                set_text(e, "Targets", &r.targets);
                set_text(e, "Ports", &r.ports);
                let (kind, value) = match &r.action {
                    Action::Direct => ("Direct", ""),
                    Action::Block => ("Block", ""),
                    Action::Proxy(s) => ("Proxy", s.as_str()),
                    Action::Chain(s) => ("Chain", s.as_str()),
                };
                set_text(e, "Action", value);
                set_attr(child(e, "Action"), "type", kind);
            },
        );
        let mut out = Vec::new();
        root.write_with_config(&mut out, xmltree::EmitterConfig::new().perform_indent(true))
            .map_err(|e| ProfileError::Encode(e.to_string()))?;
        String::from_utf8(out).map_err(|e| ProfileError::Encode(e.to_string()))
    }
}
fn child<'a>(e: &'a mut Element, n: &str) -> &'a mut Element {
    let i = e
        .children
        .iter()
        .position(|x| x.as_element().is_some_and(|e| e.name == n))
        .unwrap_or_else(|| {
            e.children.push(XMLNode::Element(Element::new(n)));
            e.children.len() - 1
        });
    e.children[i].as_mut_element().unwrap()
}
fn set_attr(e: &mut Element, n: &str, v: impl ToString) {
    e.attributes.insert(n.into(), v.to_string());
}
fn set_text(e: &mut Element, n: &str, v: impl ToString) {
    let e = child(e, n);
    e.children
        .retain(|x| !matches!(x, XMLNode::Text(_) | XMLNode::CData(_)));
    e.children.insert(0, XMLNode::Text(v.to_string()));
}
fn set_flag(e: &mut Element, n: &str, v: bool) {
    set_attr(child(e, n), "enabled", v);
}
fn rebuild(
    root: &mut Element,
    list: &str,
    item: &str,
    keys: Vec<String>,
    mut update: impl FnMut(&mut Element, usize),
) {
    let list = child(root, list);
    let old: Vec<_> = list
        .children
        .iter()
        .filter_map(XMLNode::as_element)
        .filter(|e| e.name == item)
        .cloned()
        .collect();
    list.children
        .retain(|x| !x.as_element().is_some_and(|e| e.name == item));
    for (i, key) in keys.iter().enumerate() {
        let mut e = old
            .iter()
            // Rules restore their owned source node in update, never by name.
            .find(|e| item != "Rule" && attr(e, "id", "") == key)
            .cloned()
            .unwrap_or_else(|| Element::new(item));
        update(&mut e, i);
        list.children.push(XMLNode::Element(e));
    }
}
