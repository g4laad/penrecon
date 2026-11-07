flake: { config, lib, pkgs, ... }:
let
  cfg = config.services.penrecon;
in {
  options.services.penrecon = {
    enable = lib.mkEnableOption "the local penrecon manager";
    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "penrecon package to run.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 8000;
      description = "Loopback-only HTTP port. No firewall port is opened.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.penrecon = {
      description = "Local pentest recon manager";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment.PENRECON_DATA = "/var/lib/penrecon";
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/penrecon serve --port ${toString cfg.port}";
        DynamicUser = true;
        StateDirectory = "penrecon";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/penrecon";
        Restart = "on-failure";
        RestartSec = 3;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
    };
  };
}
