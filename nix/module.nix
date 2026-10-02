# NixOS module for the RoSE server.
#
#   {
#     inputs.rose.url = "github:Lyamc/rose";
#
#     outputs = { nixpkgs, rose, ... }: {
#       nixosConfigurations.host = nixpkgs.lib.nixosSystem {
#         modules = [
#           rose.nixosModules.default
#           {
#             services.rose = {
#               enable = true;
#               openFirewall = true; # UDP 4433, QUIC
#               hostnames = [ "shell.example.com" ];
#               authorizedCerts = [ ./clients/alice.crt ];
#             };
#           }
#         ];
#       };
#     };
#   }
#
# Non-flake NixOS configurations can import this file directly:
#
#   imports = [ /path/to/rose/nix/module.nix ];
#
# Every connected shell runs as `services.rose.user`. Client certificates
# decide who may connect. They do not select a Unix account.
#
# The daemon keeps its certificate, key, and authorized clients in
# `$HOME/.config/rose` of that user (by default `/var/lib/rose/.config/rose`).
# Authorized client files must be DER-encoded and end in `.crt`.
# `rose keygen` writes that encoding to `client.crt.der`; copy it and name
# the server-side file `something.crt`.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.rose;

  settingsFile = (pkgs.formats.toml { }).generate "rose-config.toml" (
    lib.filterAttrs (_: value: value != null) {
      require_ca_certs = cfg.requireCaCerts;
      stun_servers = cfg.stunServers;
      max_sessions = cfg.maxSessions;
      # A missing key in an existing file disables idle pruning. Always write
      # the default so an absent Nix value does not change the server default.
      session_idle_timeout_secs = cfg.sessionIdleTimeoutSecs;
    }
  );

  quoteSystemd = text: ''"${lib.replaceStrings [ "\\" ''"'' ] [ "\\\\" ''\"'' ] text}"'';

  listenAddress =
    if lib.hasInfix ":" cfg.listenAddress then
      let
        bare = lib.removeSuffix "]" (lib.removePrefix "[" cfg.listenAddress);
      in
      "[${bare}]:${toString cfg.port}"
    else
      "${cfg.listenAddress}:${toString cfg.port}";

  certFileName =
    path:
    let
      base = baseNameOf (toString path);
    in
    if lib.hasSuffix ".crt.der" base then
      lib.removeSuffix ".der" base
    else if lib.hasSuffix ".crt" base then
      base
    else if lib.hasSuffix ".der" base then
      "${lib.removeSuffix ".der" base}.crt"
    else
      "${base}.crt";

  prepareScript = pkgs.writeShellScript "rose-prepare" ''
    set -eu
    umask 077
    if [ -z "''${HOME:-}" ]; then
      echo "services.rose: HOME is not set" >&2
      exit 1
    fi
    config_dir="$HOME/.config/rose"
    ${pkgs.coreutils}/bin/mkdir -p "$config_dir/authorized_certs"
    ${pkgs.coreutils}/bin/install -m 0600 ${settingsFile} "$config_dir/config.toml"
    ${lib.concatMapStrings (cert: ''
      ${pkgs.coreutils}/bin/install -m 0644 ${lib.escapeShellArg "${cert}"} \
        "$config_dir/authorized_certs/${certFileName cert}"
    '') cfg.authorizedCerts}
  '';

  execArgs = [
    (lib.getExe cfg.package)
    "server"
    "--listen"
    listenAddress
  ]
  ++ lib.concatMap (hostname: [
    "--hostname"
    hostname
  ]) cfg.hostnames
  ++ cfg.extraArgs;
in
{
  options.services.rose = {
    enable = lib.mkEnableOption "RoSE remote shell server";

    package = lib.mkOption {
      type = lib.types.package;
      description = "Package that provides the `rose` binary. The default builds this repository.";
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "rose";
      description = ''
        Unix account the server and its login shells run as.
        Client certificates authorize connections. All sessions share this account.
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "rose";
      description = "Group of the service account. Used when {option}`services.rose.createUser` is true.";
    };

    createUser = lib.mkOption {
      type = lib.types.bool;
      default = cfg.user == "rose";
      defaultText = lib.literalExpression ''user == "rose"'';
      description = ''
        Create {option}`services.rose.user` and {option}`services.rose.group`.
        Turn this off to run as an account that already exists.
      '';
    };

    extraGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wheel" ];
      description = "Extra groups for the service account when it is created by this module.";
    };

    home = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = if cfg.createUser then "/var/lib/rose" else null;
      defaultText = lib.literalExpression ''if createUser then "/var/lib/rose" else null'';
      description = ''
        Home directory of the service account.
        RoSE stores `config.toml`, `server.crt`, `server.key`, and
        `authorized_certs/` in `$HOME/.config/rose`.
        `null` leaves `HOME` to the account database.
      '';
    };

    shell = lib.mkOption {
      type = lib.types.str;
      default = "${pkgs.bashInteractive}/bin/bash";
      defaultText = lib.literalExpression ''"''${pkgs.bashInteractive}/bin/bash"'';
      description = ''
        Login shell started for each RoSE session.
        The server process exports this as `SHELL`.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0";
      example = "::";
      description = ''
        Address passed to `rose server --listen`, without the port.
        Use `::` to listen on IPv6. An address that contains `:` is wrapped
        in brackets.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 4433;
      description = "UDP port the QUIC server binds. This is the native-mode port, not the SSH bootstrap range.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Open {option}`services.rose.port` for UDP.
        RoSE native mode speaks QUIC over UDP and does not need a TCP port.
      '';
    };

    hostnames = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "shell.example.com"
        "203.0.113.10"
      ];
      description = ''
        Subject Alternative Names for the certificate generated on first start.
        Each entry is passed as `--hostname`. When this list is empty, the
        server certificate lists only `localhost`.
        An existing `server.crt` is reused and is not regenerated when this
        list changes. Delete `$HOME/.config/rose/server.crt` and `server.key`
        to mint a new certificate.
      '';
    };

    authorizedCerts = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      description = ''
        DER-encoded client certificates installed into
        `$HOME/.config/rose/authorized_certs` on each start.
        The server only loads files whose names end in `.crt`.
        A source named `client.crt.der` is installed as `client.crt`.
        Files already in that directory are left in place.
        The server reads the directory at startup, so adding a certificate
        restarts the service when it changes this option.
      '';
    };

    requireCaCerts = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Value of `require_ca_certs` in the server's `config.toml`.
        The daemon does not consult this flag. It is recorded so the file
        matches RoSE's configuration schema.
      '';
    };

    stunServers = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = null;
      example = [ "stun.example.com:3478" ];
      description = ''
        Value of `stun_servers` in `config.toml`.
        `null` omits the key, which selects the built-in STUN servers.
        The persistent daemon does not place NAT-traversal calls itself.
      '';
    };

    maxSessions = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      example = 32;
      description = ''
        Maximum number of active and detached sessions.
        `null` does not set a limit.
        New connections are refused when the limit is reached.
      '';
    };

    sessionIdleTimeoutSecs = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = 7 * 24 * 60 * 60;
      example = 86400;
      description = ''
        How long a detached session may sit idle before it is pruned.
        The default is 7 days. `0` prunes detached sessions immediately.
        `null` omits the key. In a config file that otherwise exists, a
        missing key disables idle pruning.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "rose=debug";
      description = "Value of `RUST_LOG` for the server process.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ ];
      description = "Extra arguments appended to `rose server`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.user != "root";
        message = "services.rose.user must not be root. Remote shells run as this user.";
      }
      {
        assertion = cfg.port != 0;
        message = "services.rose.port must be a fixed UDP port so the firewall can open it.";
      }
      {
        assertion = !cfg.createUser || cfg.home != null;
        message = "services.rose.home must be set when services.rose.createUser is true.";
      }
    ];

    warnings = lib.optional (cfg.hostnames == [ ]) ''
      services.rose.hostnames is empty. The certificate created on first start
      will only list localhost. Set hostnames to the name clients connect to
      before the first start.
    '';

    environment.systemPackages = [ cfg.package ];

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    users.users = lib.mkIf cfg.createUser {
      ${cfg.user} = {
        isSystemUser = true;
        inherit (cfg) group extraGroups;
        home = cfg.home;
        createHome = true;
        homeMode = "0700";
        shell = cfg.shell;
      };
    };

    users.groups = lib.mkIf cfg.createUser {
      ${cfg.group} = { };
    };

    systemd.tmpfiles.rules = lib.mkIf (cfg.createUser && cfg.home != null) [
      "d ${cfg.home} 0700 ${cfg.user} ${cfg.group} - -"
      "d ${cfg.home}/.config 0700 ${cfg.user} ${cfg.group} - -"
      "d ${cfg.home}/.config/rose 0700 ${cfg.user} ${cfg.group} - -"
      "d ${cfg.home}/.config/rose/authorized_certs 0700 ${cfg.user} ${cfg.group} - -"
    ];

    systemd.services.rose = {
      description = "RoSE remote shell server";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      environment = lib.filterAttrs (_: value: value != null) {
        HOME = cfg.home;
        SHELL = cfg.shell;
        RUST_LOG = cfg.logLevel;
      };

      # ExecStartPre is intentionally not prefixed with `+`, so systemd runs
      # it as `User`. The high-level `preStart` option would run as root.
      # Sandboxing is left off: the children of this process are login shells,
      # and systemd restrictions would apply to them too.
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        ExecStartPre = prepareScript;
        ExecStart = lib.concatMapStringsSep " " quoteSystemd execArgs;
        Restart = "on-failure";
        RestartSec = 2;
      }
      // lib.optionalAttrs cfg.createUser { Group = cfg.group; }
      // lib.optionalAttrs (cfg.home != null) { WorkingDirectory = cfg.home; };
    };
  };
}
