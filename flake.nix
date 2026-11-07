{
  description = "Local pentest recon manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
    };
  };

  outputs = { self, nixpkgs, pyproject-nix, uv2nix, pyproject-build-systems }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      packageFor = system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          frontend = pkgs.buildNpmPackage {
            pname = "penrecon-frontend";
            version = "0.1.0";
            src = ./frontend;
            nodejs = pkgs.nodejs_24;
            npmDepsHash = "sha256-iT68lngDGtZIA8kxUy7Y2yYa9kpa1fViuTLGwq5+KNs=";
            installPhase = ''
              runHook preInstall
              mkdir -p "$out"
              cp -r ../src/penrecon/web/static/ui/. "$out/"
              runHook postInstall
            '';
          };
          pythonSet = (pkgs.callPackage pyproject-nix.build.packages {
            python = pkgs.python314;
          }).overrideScope (lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
            (final: prev: {
              # The legacy sdist has no pyproject.toml declaring its backend.
              python-libnmap = prev.python-libnmap.overrideAttrs (old: {
                nativeBuildInputs = (old.nativeBuildInputs or [ ])
                  ++ final.resolveBuildSystem { setuptools = [ ]; };
              });
              penrecon = prev.penrecon.overrideAttrs (old: {
                src = lib.fileset.toSource {
                  root = ./.;
                  fileset = lib.fileset.unions [ ./pyproject.toml ./README.md ./src ];
                };
                preBuild = (old.preBuild or "") + ''
                  rm -rf src/penrecon/web/static/ui
                  mkdir -p src/penrecon/web/static/ui
                  cp -r ${frontend}/. src/penrecon/web/static/ui/
                '';
              });
            })
          ]);
        in pythonSet.mkVirtualEnv "penrecon-0.1.0" workspace.deps.default;
    in {
      packages = forAllSystems (system: {
        default = packageFor system;
        penrecon = self.packages.${system}.default;
      });
      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/penrecon";
          meta.description = "Local pentest recon manager";
        };
      });
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.python314 pkgs.uv pkgs.nodejs_24 ];
            UV_PYTHON = "${pkgs.python314}/bin/python3.14";
            UV_PYTHON_DOWNLOADS = "never";
          };
        });
      nixosModules.default = import ./nix/module.nix self;
    };
}
