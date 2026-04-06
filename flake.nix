{
  description = "suspicious — Linux file-access monitoring daemon using fanotify";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "suspicious";
          version = "0.1.0";
          src = ./.;

          vendorHash = "sha256-kPoLlIkomOnePSOBCqjZfY8skAY9TGpXVGdSSN4nH6o=";

          meta = {
            description = "Linux file-access monitoring daemon using fanotify";
            homepage = "https://github.com/nilsherzig/suspicious";
            license = pkgs.lib.licenses.mit;
            maintainers = [ ];
            mainProgram = "suspicious";
            platforms = [ "x86_64-linux" "aarch64-linux" ];
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [ pkgs.go pkgs.gopls ];
        };
      }
    );
}
