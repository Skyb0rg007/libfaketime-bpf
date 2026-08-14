# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{
  description = "libfaketime-bpf";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = lib.genAttrs systems;
    in
    {

      packages = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "faketime-bpf";
            version = "0.1.0";
            src = ./.;

            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.libseccomp ];

            nativeCheckInputs = [ pkgs.procps ];
            # ptrace/seccomp user-notify aren't implemented by qemu-user, so
            # skip checks when building aarch64-linux via binfmt emulation.
            doCheck = system == "x86_64-linux";

            installFlags = [ "PREFIX=${placeholder "out"}" ];

            meta = {
              description = "faketime without LD_PRELOAD, using ptrace + seccomp-bpf";
              license = lib.licenses.agpl3Plus;
              platforms = lib.platforms.linux;
              mainProgram = "faketime-bpf";
            };
          };
        }
      );

      devShells = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];
            packages = [
              pkgs.nixfmt
              pkgs.treefmt
              pkgs.clang-tools
              pkgs.reuse
              pkgs.libfaketime
            ];
          };
        }
      );

      checks = forEachSystem (system: {
        devShell-default = self.devShells.${system}.default;
        package-default = self.packages.${system}.default;
      });

    };
}
