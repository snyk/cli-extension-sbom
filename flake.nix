{
  description = "cli-extension-sbom development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go_1_25
            golangci-lint
            gotools
            gopls
            delve
          ];

          shellHook = ''
            export GOPATH="$HOME/go"
            export PATH="$PATH:$GOPATH/bin"
          '';
        };
      }
    );
}
