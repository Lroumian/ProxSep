use proxsep_core::profile::{Action, CredentialState, Profile};
use proxsep_core::rules::Connection;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnosticContextInput {
    pub pid: String,
    pub resolved_ips: String,
    pub interface_name: String,
    pub interface_ips: String,
}

impl DiagnosticContextInput {
    pub fn apply_to(&self, connection: &mut Connection) -> Result<(), String> {
        let pid = if self.pid.trim().is_empty() {
            None
        } else {
            Some(
                self.pid
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid PID: {}", self.pid.trim()))?,
            )
        };
        let resolved_ips = parse_ip_list("resolved IP", &self.resolved_ips)?;
        let interface_ips = parse_ip_list("interface IP", &self.interface_ips)?;
        let interface_name = self.interface_name.trim();
        if interface_name.is_empty() && !interface_ips.is_empty() {
            return Err("Interface IPs require an interface name".into());
        }

        connection.pid = pid;
        connection.resolved_ips = resolved_ips;
        connection.interfaces.clear();
        if !interface_name.is_empty() {
            connection
                .interfaces
                .insert(interface_name.into(), interface_ips);
        }
        Ok(())
    }
}

fn parse_ip_list(label: &str, value: &str) -> Result<Vec<std::net::IpAddr>, String> {
    value
        .split(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<std::net::IpAddr>()
                .map_err(|_| format!("Invalid {label}: {part}"))
        })
        .collect()
}

pub fn window_title(profile_name: &str, dirty: bool) -> String {
    format!(
        "{}{} — {}",
        profile_name,
        if dirty { " *" } else { "" },
        proxsep_core::PRODUCT_NAME
    )
}

/// Save via a new sibling file so a failed write cannot truncate the profile.
pub fn save_xml_atomic(path: &std::path::Path, xml: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "profile path has no filename",
            )
        })?
        .to_os_string();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    name.push(format!(".{}.{nonce}.tmp", std::process::id()));
    let temporary = path.with_file_name(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = file
        .write_all(xml.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    let result = result.and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Editing operations shared by the desktop panels.
pub struct ProfileEditor {
    pub profile: Profile,
    pub dirty: bool,
}

impl ProfileEditor {
    pub fn new(mut profile: Profile) -> Self {
        profile
            .rules
            .sort_by_key(|rule| rule.name.eq_ignore_ascii_case("Default"));
        Self {
            profile,
            dirty: false,
        }
    }

    pub fn move_rule(&mut self, index: usize, offset: isize) -> bool {
        let Some(destination) = index.checked_add_signed(offset) else {
            return false;
        };
        if index >= self.profile.rules.len()
            || destination >= self.profile.rules.len()
            || index == destination
        {
            return false;
        }
        if self.profile.rules[index]
            .name
            .eq_ignore_ascii_case("Default")
            || self.profile.rules[destination]
                .name
                .eq_ignore_ascii_case("Default")
        {
            return false;
        }
        let rule = self.profile.rules.remove(index);
        self.profile.rules.insert(destination, rule);
        self.dirty = true;
        true
    }

    pub fn remove_proxy(&mut self, id: u32) -> Result<(), String> {
        if self.profile.rules.iter().any(
            |rule| matches!(&rule.action, Action::Proxy(reference) if reference == &id.to_string()),
        ) {
            return Err(
                "Proxy is referenced by a rule. Change that rule before deleting the proxy.".into(),
            );
        }
        if self
            .profile
            .chains
            .iter()
            .any(|chain| chain.proxy_ids.contains(&id))
        {
            return Err(
                "Proxy is used in a chain. Remove the hop before deleting the proxy.".into(),
            );
        }
        let Some(index) = self.profile.proxies.iter().position(|proxy| proxy.id == id) else {
            return Err(format!("Proxy #{id} does not exist"));
        };
        self.profile.proxies.remove(index);
        self.dirty = true;
        Ok(())
    }

    pub fn next_proxy_id(&self) -> u32 {
        let existing = self
            .profile
            .proxies
            .iter()
            .map(|proxy| proxy.id)
            .chain(self.profile.chains.iter().map(|chain| chain.id))
            .collect::<std::collections::HashSet<_>>();
        (1..u32::MAX)
            .find(|id| !existing.contains(id))
            .expect("available proxy identifier")
    }

    pub fn replace_xml(&mut self, xml: &str) -> Result<(), String> {
        let profile = Profile::from_xml_for_current_user(xml).map_err(|error| error.to_string())?;
        self.profile = Self::new(profile).profile;
        self.dirty = false;
        Ok(())
    }

    pub fn set_encryption_mode(&mut self, mode: &str) -> Result<(), String> {
        if self
            .profile
            .options
            .encryption_mode
            .eq_ignore_ascii_case(mode)
        {
            return Ok(());
        }
        match mode {
            "account" => self
                .profile
                .enable_account_protection()
                .map_err(|error| error.to_string())?,
            "disabled" | "none" => {
                for proxy in &self.profile.proxies {
                    if self
                        .profile
                        .password_is_protected(proxy)
                        .map_err(|error| error.to_string())?
                    {
                        return Err(
                            "Unlock or replace opaque credentials before disabling encryption"
                                .into(),
                        );
                    }
                }
                self.profile.options.encryption_mode = "disabled".into();
                self.profile.credential_state = CredentialState::Plaintext;
            }
            "basic" | "master" => {
                return Err(format!(
                    "Creating {mode} credential protection is not supported; imported values are preserved"
                ));
            }
            _ => return Err(format!("Unsupported encryption mode: {mode}")),
        }
        self.dirty = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_title_uses_proxsep_identity() {
        assert_eq!(window_title("New profile", false), "New profile — ProxSep");
        assert_eq!(window_title("Profile.ppx", true), "Profile.ppx * — ProxSep");
    }

    fn fixture() -> ProfileEditor {
        let mut profile = Profile::from_xml(include_str!(
            "../../proxsep-core/tests/fixtures/default.ppx"
        ))
        .unwrap();
        profile.rules.insert(
            1,
            proxsep_core::profile::Rule {
                name: "Custom rule".into(),
                applications: "custom.exe".into(),
                ..Default::default()
            },
        );
        ProfileEditor::new(profile)
    }

    #[test]
    fn moving_a_rule_changes_priority_without_losing_its_fields() {
        let mut editor = fixture();
        let original = editor.profile.rules.clone();
        assert!(editor.move_rule(1, -1));
        assert_eq!(editor.profile.rules[0], original[1]);
        assert_eq!(editor.profile.rules[1], original[0]);
        assert!(editor.dirty);
        assert!(!editor.move_rule(0, -1));
    }

    #[test]
    fn rule_rename_and_editor_reorder_keep_imported_extension_ownership() {
        let profile = Profile::from_xml(r#"<ProxifierProfile version="102"><RuleList>
          <Rule enabled="true"><Name>Duplicate</Name><Future>first</Future><Action type="Direct"/></Rule>
          <Rule enabled="true"><Name>Duplicate</Name><Future>second</Future><Action type="Block"/></Rule>
          <Rule enabled="true"><Name>Default</Name><Action type="Direct"/></Rule>
        </RuleList></ProxifierProfile>"#).unwrap();
        let mut editor = ProfileEditor::new(profile);
        editor.profile.rules[0].name = "Renamed".into();
        assert!(editor.move_rule(0, 1));
        let reopened = Profile::from_xml(&editor.profile.to_xml().unwrap()).unwrap();
        for (index, marker) in ["second", "first"].iter().enumerate() {
            let source = reopened.rules[index].original_element.as_ref().unwrap();
            assert_eq!(
                source.get_child("Future").unwrap().get_text().as_deref(),
                Some(*marker)
            );
        }
        assert_eq!(reopened.rules[1].name, "Renamed");
        assert_eq!(reopened.rules[2].name, "Default");
    }

    #[test]
    fn default_rule_stays_pinned_after_custom_rules() {
        let mut editor = fixture();
        let before = editor.profile.clone();
        assert!(!editor.move_rule(2, -1));
        assert!(!editor.move_rule(1, 1));
        assert_eq!(editor.profile, before);
        assert!(!editor.dirty);
    }

    #[test]
    fn deletion_rejects_referenced_proxy_and_preserves_profile() {
        let mut editor = fixture();
        // Fixture has no proxies, so obtain model values via the supported XML format.
        editor.profile = Profile::from_xml("<ProxifierProfile version=\"102\" platform=\"Windows\"><Options/><ProxyList><Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>1080</Port></Proxy></ProxyList><RuleList><Rule enabled=\"true\"><Name>All</Name><Action type=\"Proxy\">1</Action></Rule></RuleList></ProxifierProfile>").unwrap();
        let before = editor.profile.clone();
        assert!(editor.remove_proxy(1).is_err());
        assert_eq!(editor.profile, before);
        editor.profile.rules[0].action = Action::Direct;
        assert!(editor.remove_proxy(1).is_ok());
        assert!(editor.profile.proxies.is_empty());
        assert!(editor.dirty);
    }

    #[test]
    fn fresh_proxy_id_does_not_collide_with_existing_proxy_or_chain() {
        let mut editor = fixture();
        editor.profile = Profile::from_xml("<ProxifierProfile version=\"102\" platform=\"Windows\"><Options/><ProxyList><Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>1080</Port></Proxy></ProxyList><ChainList><Chain id=\"2\"><Name>Chain</Name></Chain></ChainList></ProxifierProfile>").unwrap();
        assert_eq!(editor.next_proxy_id(), 3);
    }

    #[test]
    fn failed_import_preserves_unsaved_profile() {
        let mut editor = fixture();
        editor.dirty = true;
        let before = editor.profile.clone();
        assert!(editor.replace_xml("not XML").is_err());
        assert_eq!(editor.profile, before);
        assert!(editor.dirty);
        editor
            .replace_xml(include_str!(
                "../../proxsep-core/tests/fixtures/default.ppx"
            ))
            .unwrap();
        assert!(!editor.dirty);
    }

    #[test]
    fn encryption_mode_changes_only_use_supported_credential_backends() {
        let mut editor = fixture();

        editor.set_encryption_mode("account").unwrap();
        assert_eq!(editor.profile.options.encryption_mode, "account");
        assert_eq!(
            editor.profile.credential_state,
            proxsep_core::profile::CredentialState::AccountUnlocked
        );
        assert!(editor.dirty);

        editor.dirty = false;
        let before = editor.profile.clone();
        assert!(editor.set_encryption_mode("master").is_err());
        assert_eq!(editor.profile, before);
        assert!(!editor.dirty);

        editor.set_encryption_mode("disabled").unwrap();
        assert_eq!(editor.profile.options.encryption_mode, "disabled");
        assert_eq!(
            editor.profile.credential_state,
            proxsep_core::profile::CredentialState::Plaintext
        );
        assert!(editor.dirty);
    }

    #[test]
    fn diagnostic_context_populates_pid_dns_and_interface_evidence() {
        let context = DiagnosticContextInput {
            pid: "8432".into(),
            resolved_ips: "34.120.1.8; 2001:db8::8".into(),
            interface_name: "Ethernet".into(),
            interface_ips: "192.0.2.10, 2001:db8::10".into(),
        };
        let mut connection =
            proxsep_core::rules::Connection::new("Wardogs.exe", "api.example.com", 443);

        context.apply_to(&mut connection).unwrap();
        assert_eq!(connection.pid, Some(8432));
        assert_eq!(connection.resolved_ips.len(), 2);
        assert_eq!(connection.interfaces["Ethernet"].len(), 2);

        let invalid = DiagnosticContextInput {
            resolved_ips: "not-an-ip".into(),
            ..Default::default()
        };
        assert!(invalid.apply_to(&mut connection).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn disabling_unlocked_account_protection_removes_the_hash() {
        let mut profile = Profile::default();
        profile.proxies.push(proxsep_core::profile::Proxy {
            username: Some("user".into()),
            password: Some("secret".into()),
            ..Default::default()
        });
        profile.enable_account_protection().unwrap();
        let protected = profile.to_xml().unwrap();
        let loaded = Profile::from_xml_for_current_user(&protected).unwrap();
        let mut editor = ProfileEditor::new(loaded);

        editor.set_encryption_mode("disabled").unwrap();
        let plaintext = editor.profile.to_xml().unwrap();
        assert!(plaintext.contains("mode=\"disabled\""));
        assert!(!plaintext.contains("<Hash>"));
        assert!(plaintext.contains("<Password>secret</Password>"));
    }

    #[test]
    fn saving_replaces_a_complete_file_and_removes_its_temporary_file() {
        let directory = temporary_directory("save");
        let path = directory.join("profile.ppx");
        std::fs::write(&path, "existing profile").unwrap();
        let xml = fixture().profile.to_xml().unwrap();
        save_xml_atomic(&path, &xml).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), xml);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn failed_atomic_save_leaves_existing_target_intact() {
        let directory = temporary_directory("failure");
        let target = directory.join("existing-directory.ppx");
        std::fs::create_dir(&target).unwrap();
        assert!(save_xml_atomic(&target, "new profile").is_err());
        assert!(target.is_dir());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir(target).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "proxsep-desktop-test-{label}-{}-{now}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
}
