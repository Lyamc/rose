<p align="center">
  <img src="site/static/header.svg" alt="RoSE - Remote Shell Environment" width="800">
</p>

## Why RoSE?

[Mosh](https://mosh.org/) showed us that mobile-friendly remote terminals are possible, but its architecture limits what it can do. RoSE takes the same core ideas — local keystroke prediction, UDP-like unreliable transport, roaming support — and rebuilds them on modern foundations:

- **QUIC (RFC 9000) + Datagrams (RFC 9221):** Instead of a custom encrypted UDP protocol, RoSE uses QUIC. This gives us TLS 1.3 encryption for free, multiplexed reliable streams alongside unreliable datagrams, and standard X.509 certificate-based authentication. It also means RoSE servers can sit behind ordinary reverse proxies with SNI routing.
- **wezterm terminal emulator:** RoSE embeds [wezterm](https://github.com/wez/wezterm) to interpret output on the server. The current client renders text, colors, cell attributes, and screen updates. Graphics and other features need their own wire representation; embedding the emulator alone does not provide complete terminal compatibility. See the [feature boundary](doc/spec.md#terminal-feature-boundary).
- **Scrollback support:** Unlike Mosh, RoSE supports scrollback history, synchronized (at lower priority) over a dedicated QUIC stream.
- **Session persistence:** Detach and reattach to sessions seamlessly. Unlike mosh, connections are stateful at the transport layer, but new transports (for roaming) only require 1 RTT to reconnect.
- **Extensible:** QUIC's multiplexed streams make it straightforward to add features like file transfer, port forwarding, and other capabilities that currently require a separate SSH connection.

## Status

Early development. The core is functional — terminal emulation, PTY management, QUIC transport, state synchronization, scrollback, and session reconnection all work — but expect rough edges.

## Usage

Build the `rose` binary, then either run the server in the foreground or, on Windows, install it as a service.

```sh
cargo build
```

### Run the server

Native mode keeps a RoSE daemon listening for QUIC on UDP port 4433.

```sh
rose server
rose server --listen 0.0.0.0:4433 --hostname myserver.example.com
```

On first start the server writes a self-signed certificate under the config directory. Authentication is mutual TLS:

1. `rose keygen` generates a client certificate.
2. Copy that certificate into the server's `authorized_certs/` directory.
3. For a self-signed server certificate, the client trusts it on first use and caches it in `known_hosts/`.
4. A server behind a reverse proxy with a CA-signed certificate does not need that cache.

Config is `config.toml` next to the `rose` executable when that file exists.
Otherwise Unix uses `~/.config/rose/` and Windows uses `%ProgramData%\RoSE\`
(the service data directory). `--config-dir` overrides either default.

```sh
rose connect myserver.example.com
rose connect myserver.example.com --port 4433
rose connect myserver.example.com --retry-limit -1 --always-retry
```

Change a running server without restarting it. `rose ctl` writes `config.toml`
(and `authorized_certs/` for authorize/revoke); the server rereads those files.

```sh
rose ctl show
rose ctl set require_client_certs false
rose ctl set max_sessions 8
rose ctl authorize ~/.config/rose/client.crt.der --name lyam
rose ctl revoke lyam
rose ctl pending
rose ctl set pairing true
rose ctl approve 12345678
rose ctl totp init
```

Pairing is off by default. After `rose ctl set pairing true`, an unauthorized `rose connect` stays up and prints a numeric code (default 8 digits, 2 minutes). On the server, `rose ctl approve <code>` (alias `rose ctl pair`) copies that certificate into `authorized_certs/`. Shorter codes expire faster (2 digits 15s, 4 digits 30s, 6 digits 1 minute, 8 digits 2 minutes, up to 1 hour). `rose ctl deny` discards one.

`totp_required` challenges every new login with a 6-digit TOTP code; first login prints an `otpauth://` URI. `rose ctl totp init` stores an operator secret in `operator.totp` so `approve` also needs `--totp`. OpenID Connect device login is available when `sso_issuer` and `sso_client_id` are set.

`require_client_certs` defaults to `true`. When it is `false`, any client can
connect. Setting it back to `true` closes sessions that no longer have an
authorized certificate. `alias rosectl='rose ctl'` if you want a shorter name.

If the server is listening but rejects the client (the client certificate is
missing from `authorized_certs/`, or the handshake fails for another
authentication reason), `rose connect` prints the reason and stops. Use
`--always-retry` to keep trying anyway. `--retry-limit` caps the number of
initial attempts (`-1` is unlimited; the default is 10). `--retry-interval
<seconds>` uses a constant delay; the default schedule is 1s, 2s, 3s, 5s, 5s,
5s, 10s, 10s, 10s, 30s, then 60s doubling up to one hour. The same keys can be
set in `config.toml` as `always_retry`, `retry_limit`, and
`retry_interval_secs`.

### Windows service

From an elevated prompt, install the server so it starts at boot. This copies the binary you just built, registers the service, opens the listen port in Windows Firewall, and adds the install directory to the system `PATH`. Open a new terminal before running `rose`.

```sh
rose service install
rose service install --listen 0.0.0.0:4433 --hostname myserver.example.com
rose service uninstall
```

`install` does all of the following:

- Copies `rose.exe` to `%ProgramFiles%\RoSE\rose.exe`.
- Registers an auto-start service named `RoSE`. The service account is LocalSystem, so every connected shell runs as LocalSystem. Windows restarts the service up to three times if it crashes.
- Adds an inbound UDP firewall rule named `RoSE` for the listen port. QUIC is UDP; a TCP rule does not open the server.
- Adds `%ProgramFiles%\RoSE` to the system `PATH` when that directory is not already there. The registry value keeps its existing type, so entries such as `%SystemRoot%\system32` stay unexpanded. Terminals that are already open keep their old `PATH` until they are started again.
- Starts the service after the socket is bound.

Certificates, `config.toml`, and `service.log` are stored in `%ProgramData%\RoSE`. Put each DER client certificate (`client.crt.der` from `rose keygen`) in `%ProgramData%\RoSE\authorized_certs\` and name it with a `.crt` suffix, or use `rose ctl authorize`. `rose ctl` finds that directory by default on Windows. The service listens when that directory is empty and refuses every client until a matching `.crt` is present, unless `require_client_certs` is `false`. Adding or removing a certificate, and `rose ctl set`, take effect immediately; a restart is not required. `--listen` and `--hostname` match `rose server`. A portable layout is a `rose.exe` with `config.toml` beside it; that directory is used instead of `%ProgramData%\RoSE`.

`uninstall` stops the service, deletes the `RoSE` firewall rule, removes `%ProgramFiles%\RoSE` from the system `PATH`, and deletes that directory. It leaves `%ProgramData%\RoSE` in place, including the server certificate and authorized clients.

### NixOS

This repository is a flake. The NixOS module builds `rose` and runs it as a systemd service. `services.rose.openFirewall` opens the QUIC UDP port (4433 by default). Sessions run as `services.rose.user`. That is a `rose` system account unless you point it at an existing user. Certificates, `config.toml`, and `authorized_certs/` are stored in that account's `$HOME/.config/rose` (`/var/lib/rose/.config/rose` for the default account).

```nix
{
  inputs.rose.url = "github:Lyamc/rose";

  outputs = { nixpkgs, rose, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        rose.nixosModules.default
        {
          services.rose = {
            enable = true;
            openFirewall = true;
            hostnames = [ "shell.example.com" ];
            authorizedCerts = [ ./clients/alice.crt ];
          };
        }
      ];
    };
  };
}
```

A configuration without a flake can import the module by path:

```nix
imports = [ /path/to/rose/nix/module.nix ];

services.rose.enable = true;
services.rose.openFirewall = true;
```

`hostnames` is written into the server certificate on first start. Delete `server.crt` and `server.key` in the config directory before restarting if that list changes. Files in `authorizedCerts` must be DER-encoded. `rose keygen` writes that encoding to `client.crt.der`. The server only loads files in `authorized_certs/` whose names end in `.crt`. It listens when that directory is empty and refuses every client until a matching `.crt` is present. Adding or removing a certificate takes effect immediately.

### SSH bootstrap mode

No server daemon is required. RoSE SSHs in, starts a temporary server, exchanges certificates, and switches to QUIC:

```sh
rose connect --ssh user@myserver.example.com
```

### Escape sequences

While connected, press `Enter` then `~` to access escape commands:

- `~.` — disconnect
- `~d` — detach and print a command to reattach to the same session
- `~~` — send a literal `~`
- `~?` — show help

The reattach command includes `--session <id>` and preserves the host, port, and any explicit certificate paths. Run that command to resume the saved shell.

## Development

See [`AGENTS.md`](AGENTS.md) for full development guidelines.

```sh
cargo fmt --all                                         # format
cargo clippy --workspace --all-targets                  # lint
cargo nextest run --all --no-fail-fast                  # test
cargo +nightly llvm-cov-easy nextest --workspace --branch  # coverage
cargo deny check                                        # security audit
cargo bench -p rose                                     # benchmarks
```

## Architecture

See [`doc/spec.md`](doc/spec.md) for the full specification.

RoSE is a Cargo workspace with two crates:

- **`lib/`** — library crate (`rose`) containing core logic: terminal emulation, state synchronization protocol (SSP), QUIC transport, PTY management, scrollback sync, and session persistence.
- **`cli/`** — binary crate (`rose-cli`, binary name `rose`) providing subcommands: `connect`, `server`, `keygen`, and `service`. Man pages are generated at build time.

Key dependencies: [quinn](https://github.com/quinn-rs/quinn) (QUIC), [wezterm-term](https://github.com/wez/wezterm) (terminal emulation), [portable-pty](https://docs.rs/portable-pty) (PTY management), [rustls](https://github.com/rustls/rustls) (TLS 1.3), [rcgen](https://github.com/rustls/rcgen) (certificate generation).

## License

GPL-3.0-or-later — RoSE includes [tests ported from Mosh](lib/tests/mosh_ported.rs), which is GPL-3.0-or-later.
