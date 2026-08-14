# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{
  pkgs ? import <nixpkgs> { },
}:

pkgs.stdenv.mkDerivation {
  pname = "faketime-bpf";
  version = "0.1.0";
  src = ./.;

  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ pkgs.libseccomp ];

  nativeCheckInputs = [ pkgs.procps ];
  doCheck = true;

  installFlags = [ "PREFIX=$(out)" ];

  meta = {
    description = "faketime without LD_PRELOAD, using ptrace + seccomp-bpf";
    license = pkgs.lib.licenses.agpl3Plus;
    platforms = pkgs.lib.platforms.linux;
    mainProgram = "faketime-bpf";
  };
}
