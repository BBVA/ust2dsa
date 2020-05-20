{ nixpkgs ? import <nixpkgs> {} }:
let
  inherit (nixpkgs) pkgs;
  inherit (pkgs) haskellPackages;

  haskellDeps = ps: with ps; [
    base
    parsec
    bifunctors
    bytestring
    versions
    text
    cmdargs
    utility-ht
    containers
    split
    strict
    zlib
    mtl
    download
    lzma
  ];

  ghc = haskellPackages.ghcWithPackages haskellDeps;

  nixPackages = [
    ghc
    pkgs.gdb
    haskellPackages.cabal-install
  ];

  ust2dsa = pkgs.stdenv.mkDerivation {
    name = "ust2dsa";
    buildInputs = nixPackages;
    src = ./.;
    buildPhase = ''
      # https://github.com/NixOS/nixpkgs/issues/16144#issuecomment-225422439
      HOME="$TMP" cabal install --installdir=.
    '';
    installPhase = ''
      mkdir -p $out/bin
      cp ust2dsa $out/bin
    '';
  };
in
  pkgs.snapTools.makeSnap {
    meta = {
      name = "ust2dsa";
      version = "0.1.0";
      license = "Apache-2.0";
      summary = "Debsecan database generator for Ubuntu CVE Tracker";
      description = "This tool aims to enable Ubuntu users to leverage Debian's debsecan vulnerability analysis and reporting tool.";
      type = "app";
      architectures = [ "amd64" ];
      confinement = "strict";
      apps.ust2dsa.command = "${ust2dsa}/bin/ust2dsa";
    };
  }
