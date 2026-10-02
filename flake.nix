{
  description = "RoSE remote shell environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEach = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forEach (system: {
        default = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix { };
      });

      overlays.default = final: _prev: {
        rose = self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      nixosModules.default = ./nix/module.nix;
      nixosModules.rose = self.nixosModules.default;
    };
}
