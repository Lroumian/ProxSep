use proxsep_service::{EngineConfig, SERVICE_PASSWORD_ENV, load_profile};
use std::{ffi::OsString, sync::OnceLock, time::Duration};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

static SERVICE_CONFIG: OnceLock<(String, EngineConfig)> = OnceLock::new();
define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(name: String, config: EngineConfig) -> Result<(), String> {
    SERVICE_CONFIG
        .set((name.clone(), config))
        .map_err(|_| "service configuration is already initialized")?;
    service_dispatcher::start(name, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("service failure: {error}");
    }
}

fn state(current_state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
    let pending = matches!(
        current_state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: u32::from(pending),
        wait_hint: if pending {
            Duration::from_secs(10)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

fn run_service() -> Result<(), String> {
    let (name, config) = SERVICE_CONFIG
        .get()
        .ok_or("service configuration unavailable")?;
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let status = service_control_handler::register(name, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| e.to_string())?;
    status
        .set_service_status(state(ServiceState::StartPending, ServiceExitCode::Win32(0)))
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let executor = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        executor.block_on(async {
            let listener = proxsep_service::start_engine(config).await?;
            let running = status
                .set_service_status(state(ServiceState::Running, ServiceExitCode::Win32(0)))
                .map_err(|e| e.to_string());
            if let Err(error) = running {
                listener.stop().await;
                return Err(error);
            }
            while !*stop_rx.borrow_and_update() {
                if stop_rx.changed().await.is_err() {
                    break;
                }
            }
            let pending = status
                .set_service_status(state(ServiceState::StopPending, ServiceExitCode::Win32(0)))
                .map_err(|e| e.to_string());
            listener.stop().await;
            pending
        })
    })();
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status
        .set_service_status(state(ServiceState::Stopped, exit_code))
        .map_err(|e| e.to_string())?;
    result
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| e.to_string())
}

pub fn install(
    name: &str,
    config: &EngineConfig,
    account: &str,
    auto_start: bool,
) -> Result<(), String> {
    load_profile(config)?;
    if account.trim().is_empty() || account.chars().any(char::is_control) {
        return Err("invalid service account".into());
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    if !executable.is_absolute() {
        return Err("service executable path must be absolute".into());
    }
    let built_in = [
        "NT AUTHORITY\\LocalService",
        "NT AUTHORITY\\NetworkService",
        "LocalSystem",
    ]
    .iter()
    .any(|name| account.eq_ignore_ascii_case(name));
    let password = if built_in {
        None
    } else {
        std::env::var_os(SERVICE_PASSWORD_ENV)
    };
    if !built_in && password.is_none() {
        return Err(format!(
            "custom service accounts require {SERVICE_PASSWORD_ENV} in the installer environment"
        ));
    }
    let info = ServiceInfo {
        name: name.into(),
        display_name: format!("ProxSep ({name})").into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if auto_start {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::OnDemand
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec![
            "service".into(),
            "--name".into(),
            name.into(),
            "--profile".into(),
            config.profile_path.as_os_str().into(),
            "--listen".into(),
            config.listen.to_string().into(),
            "--application".into(),
            config.application.clone().into(),
        ],
        dependencies: vec![],
        account_name: Some(account.into()),
        account_password: password,
    };
    let service = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| e.to_string())?;
    service
        .set_description("ProxSep profile-based proxy routing service (loopback SOCKS5 clients)")
        .map_err(|e| {
            format!("service '{name}' was created but its description could not be set: {e}")
        })?;
    println!("Service {name} registered under {account}; it has not been started");
    Ok(())
}

pub fn uninstall(name: &str) -> Result<(), String> {
    let service = manager(ServiceManagerAccess::CONNECT)?
        .open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE)
        .map_err(|e| e.to_string())?;
    if service
        .query_status()
        .map_err(|e| e.to_string())?
        .current_state
        != ServiceState::Stopped
    {
        return Err("stop the service before uninstalling it".into());
    }
    service.delete().map_err(|e| e.to_string())?;
    println!("Service {name} marked for deletion");
    Ok(())
}

pub fn status(name: &str) -> Result<(), String> {
    let service = manager(ServiceManagerAccess::CONNECT)?
        .open_service(name, ServiceAccess::QUERY_STATUS)
        .map_err(|e| e.to_string())?;
    let status = service.query_status().map_err(|e| e.to_string())?;
    println!(
        "{name}: {:?}, PID {:?}, exit {:?}",
        status.current_state, status.process_id, status.exit_code
    );
    Ok(())
}

pub fn start(name: &str) -> Result<(), String> {
    let service = manager(ServiceManagerAccess::CONNECT)?
        .open_service(name, ServiceAccess::START)
        .map_err(|e| e.to_string())?;
    service.start::<&str>(&[]).map_err(|e| e.to_string())?;
    println!("Start requested for {name}");
    Ok(())
}

pub fn stop(name: &str) -> Result<(), String> {
    let service = manager(ServiceManagerAccess::CONNECT)?
        .open_service(name, ServiceAccess::STOP)
        .map_err(|e| e.to_string())?;
    service.stop().map_err(|e| e.to_string())?;
    println!("Stop requested for {name}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_states_have_checkpoints_and_running_accepts_stop() {
        for pending in [ServiceState::StartPending, ServiceState::StopPending] {
            let status = state(pending, ServiceExitCode::Win32(0));
            assert_eq!(status.checkpoint, 1);
            assert_eq!(status.wait_hint, Duration::from_secs(10));
            assert!(status.controls_accepted.is_empty());
        }
        let running = state(ServiceState::Running, ServiceExitCode::Win32(0));
        assert_eq!(running.checkpoint, 0);
        assert_eq!(running.wait_hint, Duration::ZERO);
        assert!(
            running
                .controls_accepted
                .contains(ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)
        );
        let failed = state(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1));
        assert_eq!(failed.exit_code, ServiceExitCode::ServiceSpecific(1));
    }
}
