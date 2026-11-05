{
  description = "Confidential agent runtime";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/1f607aa79b6356ed45d3cd3c8079c196e79efa2c"; # nixos-26.05

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # The Secure Boot signing keys live outside the repository; images are built with
      # `--impure` and CLOVELLY_SIGNING_KEYS naming their directory (release/nix.sh).
      keys = builtins.getEnv "CLOVELLY_SIGNING_KEYS";
      clovelly = pkgs.callPackage ./image {
        signingKeys =
          if keys == "" then
            throw "set CLOVELLY_SIGNING_KEYS to the signing-key directory and build with --impure"
          else
            builtins.path {
              path = keys;
              name = "clovelly-signing-keys";
            };
      };
    in
    {
      packages.${system} = {
        inherit (clovelly)
          cell-agent
          egress-proxy
          measure
          verifier
          key-helper
          verifier-image
          clovelly-keys-image
          verifier-image-oci
          clovelly-keys-image-oci
          verifier-image-test-clock
          runsc
          attest-tools
          base-bundle
          image-prod
          image-test
          image-prod-unsigned
          image-testb
          image-test-altered
          image-test-wrong-roothash
          image-test-unsigned
          image-test-otherkey
          manifest
          ;
        default = clovelly.image-test;
      };
    };
}
