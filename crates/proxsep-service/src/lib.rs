use std::{net::SocketAddr, path::PathBuf};

pub const DEFAULT_SERVICE_NAME: &str = "ProxSep";
pub const SERVICE_PASSWORD_ENV: &str = "PROXSEP_SERVICE_PASSWORD";

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub profile_path: PathBuf,
    pub listen: SocketAddr,
    pub application: String,
}

impl EngineConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.profile_path.is_absolute() {
            return Err("profile path must be absolute".into());
        }
        if !self.listen.ip().is_loopback() {
            return Err("unauthenticated listener must bind a loopback address".into());
        }
        if self.application.trim().is_empty() || self.application.chars().any(char::is_control) {
            return Err(
                "application identity must be nonempty and contain no control characters".into(),
            );
        }
        Ok(())
    }
}

pub fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("service name must be 1-80 ASCII letters, digits, '-' or '_'".into());
    }
    Ok(())
}

pub fn load_profile(config: &EngineConfig) -> Result<proxsep_core::profile::Profile, String> {
    config.validate()?;
    let xml = std::fs::read_to_string(&config.profile_path)
        .map_err(|e| format!("cannot read profile: {e}"))?;
    proxsep_core::profile::Profile::from_xml_for_current_user(&xml).map_err(|e| e.to_string())
}

pub async fn start_engine(
    config: &EngineConfig,
) -> Result<proxsep_runtime::ListenerHandle, String> {
    let runtime = proxsep_runtime::Runtime::new(load_profile(config)?);
    runtime
        .start_socks5(&config.listen.to_string(), config.application.clone())
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_service_uses_proxsep_identity() {
        assert_eq!(DEFAULT_SERVICE_NAME, "ProxSep");
        assert_eq!(SERVICE_PASSWORD_ENV, "PROXSEP_SERVICE_PASSWORD");
    }
    fn config() -> EngineConfig {
        EngineConfig {
            profile_path: std::env::current_dir().unwrap().join("profile.ppx"),
            listen: "127.0.0.1:1080".parse().unwrap(),
            application: "service-client.exe".into(),
        }
    }

    #[test]
    fn rejects_public_unauthenticated_listener() {
        let mut c = config();
        c.listen = "0.0.0.0:1080".parse().unwrap();
        assert!(c.validate().is_err());
        c.listen = "[::]:1080".parse().unwrap();
        assert!(c.validate().is_err());
        c.listen = "[::1]:1080".parse().unwrap();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn service_profile_paths_are_absolute() {
        let mut c = config();
        c.profile_path = "profile.ppx".into();
        assert!(c.validate().is_err());
        c.profile_path = std::env::current_dir()
            .unwrap()
            .join("directory with spaces/profile.ppx");
        assert!(c.validate().is_ok());
    }

    #[test]
    fn requires_a_nonempty_application_identity() {
        let mut c = config();
        c.application = "  ".into();
        assert!(c.validate().is_err());
        c.application = "app\0.exe".into();
        assert!(c.validate().is_err());
        assert!(config().validate().is_ok());
    }

    #[test]
    fn service_names_cannot_be_paths_or_control_sequences() {
        for name in ["", "Bad/Name", "Bad\\Name", "Bad\nName"] {
            assert!(validate_service_name(name).is_err());
        }
        assert!(validate_service_name(DEFAULT_SERVICE_NAME).is_ok());
    }
}
