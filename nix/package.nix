{
  lib,
  rustPlatform,
  rustc,
}:

assert lib.assertMsg (lib.versionAtLeast rustc.version "1.85.0") ''
  RoSE needs Rust 1.85 or newer (edition 2024). Use a recent nixpkgs, such as nixos-unstable.
'';

# Regenerate with `cargo generate-lockfile`, then set this from the
# `got:` line of a failed `nix build` (`cargoHash = "";` forces that line).
rustPlatform.buildRustPackage (_finalAttrs: {
  pname = "rose";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../cli
      ../lib
    ];
  };

  cargoHash = "sha256-A80zwcAXfPXdjddmATW/Bnd+3hyEm403U+EVImpw+BQ=";

  # The Rust workspace is tested with `cargo nextest` in CI. The Nix build
  # only produces the `rose` binary.
  doCheck = false;

  postInstall = ''
    mkdir -p "$out/share/man/man1"
    find target -type f -name 'rose*.1' -exec cp {} "$out/share/man/man1/" \;
  '';

  meta = {
    description = "Remote Shell Environment, a Mosh-inspired terminal over QUIC";
    homepage = "https://rose.nikhiljha.com/";
    license = lib.licenses.gpl3Plus;
    mainProgram = "rose";
    platforms = lib.platforms.linux;
  };
})
