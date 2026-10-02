{
  lib,
  fetchurl,
  rustPlatform,
  rustc,
}:

assert lib.assertMsg (lib.versionAtLeast rustc.version "1.85.0") ''
  RoSE needs Rust 1.85 or newer (edition 2024). Use a recent nixpkgs, such as nixos-unstable.
'';

# wezterm-term includes a terminfo file that lives outside that crate.
# Cargo's vendor directory keeps only the crate, so the file is restored
# from the same wezterm commit as Cargo.lock.
let
  weztermRev = "cab25161054c50fd6c705db4ceefef0f1e5a9575";
  weztermTerminfo = fetchurl {
    url = "https://raw.githubusercontent.com/wezterm/wezterm/${weztermRev}/termwiz/data/wezterm";
    hash = "sha256-ml4XxNLolQMmMyjA/KwosyxNaq922l2OXt/88vfpI4c=";
  };
in

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

  preConfigure = ''
    mapfile -t crates < <(find "$NIX_BUILD_TOP" -type d -name 'wezterm-term-*')
    if [ ''${#crates[@]} -eq 0 ]; then
      echo "wezterm-term crate not found in the cargo vendor directory" >&2
      exit 1
    fi
    for crate in "''${crates[@]}"; do
      install -D -m 0644 ${weztermTerminfo} "$(dirname "$crate")/termwiz/data/wezterm"
    done
  '';

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
