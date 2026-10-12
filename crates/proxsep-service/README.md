# Windows service and console daemon

Build with `cargo build -p proxsep-service --release`.

Run interactively:

```powershell
proxsep-service.exe run --profile 'C:\Profiles\Profile.ppx' --listen 127.0.0.1:1080
```

Ctrl+C stops the loopback SOCKS5 listener and cancels/drains its active tunnels.
The engine uses the same profile validation, rule decisions, DNS policy and
proxy protocols as the CLI/desktop runtime. Its configured application label
takes precedence in application-name rules. The runtime can attempt a TCP-table
PID snapshot, but this is not authenticated kernel capture and process/path
queries may fail across service-account boundaries.

SCM management commands are explicit:

```powershell
proxsep-service.exe install --profile 'C:\Profiles\Profile.ppx'
proxsep-service.exe start
proxsep-service.exe status
proxsep-service.exe stop
proxsep-service.exe uninstall
```

Installation requires the user's SCM installation privileges and registers an
on-demand service under `NT AUTHORITY\LocalService`. It does not start the service.
`--auto-start` and `--account` must be supplied explicitly to change these defaults.
LocalService must have read permission on the chosen profile; the installer does
not modify profile ACLs. Custom account passwords are read from the installer's
`PROXSEP_SERVICE_PASSWORD` environment variable, never from command arguments.

The executable and profile paths are absolute. The Windows service API quotes
executable/argument paths when constructing the SCM command line. `uninstall`
refuses to delete a running service. Stop/Shutdown signal the async engine,
report StopPending, drain listeners and then report Stopped. Startup errors
report service-specific exit code 1; console mode prints detailed errors.

No service is installed, started, stopped or removed during automated tests.
The lifecycle test runs only a temporary loopback listener. SCM hosting, account
permissions and restart behavior still require testing in an explicitly
user-managed Windows service installation.
