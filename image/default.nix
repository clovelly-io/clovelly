# The cell images, the measurement predictor and the verifier container.
#
# A UKI (kernel, busybox initrd, command line) on the ESP boots straight from firmware
# under Secure Boot: the UKI is signed with our db key, and GCE images carry our own PK,
# KEK and db (the image import sets them). The initrd opens the root partition through dm-verity,
# using the root hash from the UKI's command line, and switches to it. Root is a
# read-only erofs; all writable state is tmpfs. Two variants come from one recipe:
#
#   image-prod  no serial console, no results channel; the agent boots the cell.
#               Its release id is `clovelly-<version>`, the workspace version.
#   image-test  serial console, the Google attestation tools and curl; init runs the
#               harness and returns results by signed-URL upload and on serial, or
#               (role `cell`) runs the cell with memory scans at its end, or (role
#               `impostor`) serves an unverified certificate for the SDK to refuse.
#   image-testb image-test as a second release (`clovelly-0.1.0-testb`), so one release can
#               expire in a test while cells of another run on (phase 2 criterion 5).
#
# Test-only images for refusal checks, built from image-test's root (their
# measurements are never published):
#
#   image-test-altered         one command-line token changed (panic=-1 -> panic=0)
#   image-test-wrong-roothash  clovelly.roothash= names another root; the initrd opens the
#                              real one from a hash baked into it
#   image-test-unsigned        the UKI without a signature
#   image-test-otherkey        the UKI signed by a key that is not in db
#
# The release pipeline (phase 5) builds image-prod-unsigned and image-test-unsigned on
# two builders and compares them: they need no key, so anyone can rebuild them, and
# their measurements are the signed images' (Authenticode leaves out the signature).
#
# Each image output holds disk.raw.tar.gz (GCE import format), uki.efi, roothash,
# cmdline, release, root-offset, disk.sha256, predicted-rtmr (RTMR1 and RTMR2 from
# `measure`, with every extension) and versions (the components' versions, for the
# release notes). Reproducibility is described in DETERMINISM.md.
{
  lib,
  pkgs,
  # A directory holding db.key/db.pem (our Secure Boot db signing key) and
  # other.key/other.pem (a key db does not trust). Outside the repository.
  signingKeys,
}:
let
  # The workspace's version: tag v<version> is release clovelly-<version>.
  version = (lib.importTOML ../Cargo.toml).workspace.package.version;
  # Our own code's licence (LICENSE). The pinned nixpkgs has no entry for it.
  fsl = {
    spdxId = "FSL-1.1-ALv2";
    fullName = "Functional Source License, Version 1.1, ALv2 Future License";
  };
  kernel = pkgs.linuxPackages_6_18.kernel;
  inherit (pkgs) busybox kmod cryptsetup;

  # gVisor's release build, vendored unmodified: runsc plus its gvisor-bin sidecars,
  # which runsc finds next to itself.
  runsc = pkgs.stdenvNoCC.mkDerivation rec {
    pname = "runsc";
    version = "20261019.0";
    src = pkgs.fetchurl {
      url = "https://storage.googleapis.com/gvisor/releases/release/${version}/x86_64/gvisor.tar.bz2";
      sha512 = "7cbc2aeeee809dcccfb40e612504a1b76f2c119790cee59e482f7b35428cccc4f71705e7e322442d07d1f7d29b5d9e72e31319fc3088d6dcbec9fc7c1f0d8881";
    };
    unpackPhase = "tar xjf $src";
    installPhase = ''
      install -Dm755 runsc $out/bin/runsc
      cp -r gvisor-bin $out/bin/gvisor-bin
    '';
    dontFixup = true;
    meta.license = lib.licenses.asl20;
  };

  # One Rust package from the workspace.
  rust =
    pname: extra:
    pkgs.rustPlatform.buildRustPackage (
      {
        inherit pname version;
        src = lib.fileset.toSource {
          root = ./..;
          fileset = lib.fileset.unions [
            ../Cargo.toml
            ../Cargo.lock
            ../crates
          ];
        };
        cargoLock.lockFile = ../Cargo.lock;
        cargoBuildFlags = [
          "-p"
          pname
        ];
        doCheck = false; # `cargo test --workspace` runs the tests
        meta.license = fsl;
      }
      // extra
    );

  # Static, so the same binary runs on the host and bind-mounted into a sandbox.
  cell-agent = rust "cell-agent" {
    # buildRustPackage passes --target, so RUSTFLAGS reach only target artifacts and
    # build scripts stay dynamically linked against the normal glibc.
    env.RUSTFLAGS = "-C target-feature=+crt-static -L native=${pkgs.glibc.static}/lib";
  };
  # The egress proxy, its own process since phase 4; static like the agent.
  egress-proxy = rust "egress-proxy" {
    env.RUSTFLAGS = "-C target-feature=+crt-static -L native=${pkgs.glibc.static}/lib";
  };
  measure = rust "measure" { };
  verifier = rust "verifier" { };
  # The verifier whose clock CLOVELLY_TEST_CLOCK_OFFSET_SECS moves: staging tests only
  # (phase 5 criteria 3 to 5), never a customer's verifier.
  verifier-test-clock = rust "verifier" {
    pname = "verifier-test-clock";
    buildFeatures = [ "test-clock" ];
  };

  # The reference key helpers (docs/key-helper.md), which the verifier reaches on its loopback.
  key-helper = rust "key-helper" { };

  # One published image: a single binary and the CA bundle. Fixed creation time, so the
  # digest depends only on its contents.
  publishedImage =
    name: entrypoint:
    pkgs.dockerTools.buildLayeredImage {
      inherit name;
      tag = version;
      created = "1970-01-01T00:00:01Z";
      contents = [ pkgs.cacert ];
      config = {
        Entrypoint = [ entrypoint ];
        Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
        Labels."org.opencontainers.image.source" = "https://github.com/clovelly-io/clovelly";
      };
    };

  # An image as the release publishes it: its layers compressed once, here, so the digest in
  # the signed payload is the digest in the registry (oci-layout.py).
  ociLayout =
    name: image:
    pkgs.runCommand "${name}-oci" { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python3 ${./oci-layout.py} ${image} $out
    '';

  verifier-image = publishedImage "verifier" "${verifier}/bin/verifier";
  clovelly-keys-image = publishedImage "clovelly-keys" "${key-helper}/bin/clovelly-keys";
  verifier-image-oci = ociLayout "verifier" verifier-image;
  clovelly-keys-image-oci = ociLayout "clovelly-keys" clovelly-keys-image;

  # The test-clock verifier for the staging job, built the same way.
  verifier-image-test-clock = pkgs.dockerTools.buildLayeredImage {
    name = "verifier-test-clock";
    tag = version;
    created = "1970-01-01T00:00:01Z";
    contents = [ pkgs.cacert ];
    config = {
      Entrypoint = [ "${verifier-test-clock}/bin/verifier" ];
      Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
    };
  };

  # Google's attestation checkers, pinned by commit; test image only.
  goTdxGuest = pkgs.buildGoModule {
    pname = "go-tdx-guest-tools";
    version = "0-unstable-2026-10-14";
    src = pkgs.fetchFromGitHub {
      owner = "google";
      repo = "go-tdx-guest";
      rev = "23b3eac9db39ba4e1df1426bacb3bfa3a7018e97";
      hash = "sha256-3OO1bYDF6rQGe34kUBMSgsQaoKy4XI4Nk5eudxoqZoo=";
    };
    vendorHash = "sha256-adb439sXC1OLdEmf4EEw3OxUuSW/1bdpVZMqWLFYKDk=";
    subPackages = [
      "tools/check"
      "tools/gceprovenance"
    ];
    env.CGO_ENABLED = "0";
    doCheck = false;
    meta.license = lib.licenses.asl20;
  };
  gcetcbendorsement = pkgs.buildGoModule {
    pname = "gcetcbendorsement";
    version = "0-unstable-2026-10-09";
    src = pkgs.fetchFromGitHub {
      owner = "google";
      repo = "gce-tcb-verifier";
      rev = "e3ac0cb1bf1072be139a2971534757e2ade492a5";
      hash = "sha256-IV+YQGz0f4Ri3P3nJZqeHIXsoLWEpuhNaNR+wuQEvSA=";
    };
    # At this commit the module's own go.mod pins an older gce-tcb-verifier that lacks
    # symbols it uses, so it builds only through the repo's go.work, from the root.
    proxyVendor = true;
    env.CGO_ENABLED = "0";
    vendorHash = "sha256-QaA8dKU8Tdc9sGjFMOOP8UwUHz0FjBLpEdSplqGJvdQ=";
    subPackages = [ "gcetcbendorsement/cli" ];
    postInstall = "mv $out/bin/cli $out/bin/gcetcbendorsement";
    doCheck = false;
    meta.license = lib.licenses.asl20;
  };
  attest-tools = pkgs.symlinkJoin {
    name = "attest-tools";
    meta.license = lib.licenses.asl20;
    paths = [
      goTdxGuest
      gcetcbendorsement
    ];
  };

  python = pkgs.python3;

  # The sandbox base bundle's root: python3, pinned by its store path (which encodes
  # its derivation hash), and busybox for sh, echo and sleep. The agent writes each
  # sandbox's config.json; this is only the rootfs.
  base-bundle =
    pkgs.runCommand "base-bundle"
      {
        meta.license = fsl; # our assembly of python3 and busybox
        closure = pkgs.closureInfo {
          rootPaths = [
            python
            busybox
          ];
        };
      }
      ''
        mkdir -p $out/rootfs/{bin,etc,tmp,work,volume,nix/store}
        xargs -a $closure/store-paths cp -a -t $out/rootfs/nix/store
        for a in $(${busybox}/bin/busybox --list); do
          ln -s ${busybox}/bin/busybox $out/rootfs/bin/$a
        done
        ln -s ${python}/bin/python3 $out/rootfs/bin/python3
        echo 'root:x:0:0:root:/tmp:/bin/sh' > $out/rootfs/etc/passwd
        echo 'root:x:0:' > $out/rootfs/etc/group
        # Mount points for what the cell binds into every sandbox (phase 3): its resolver
        # (the egress proxy) and its trust store (public roots and the in-cell CA).
        mkdir -p $out/rootfs/etc/ssl/certs
        touch $out/rootfs/etc/resolv.conf $out/rootfs/etc/ssl/certs/ca-certificates.crt
        echo ${python} > $out/python
      '';

  # Kernel modules the boot path and harness load; modprobe pulls in dependencies.
  # The licence is recorded for the manifest; meta does not change the output.
  modules = lib.addMetaAttrs { license = lib.licenses.gpl2Only; } (pkgs.makeModulesClosure {
    # The kernel ships its modules in a separate output.
    kernel = kernel.modules;
    firmware = pkgs.runCommand "no-firmware" { } "mkdir -p $out/lib/firmware";
    rootModules = [
      "af_packet"
      "nvme"
      "dm-verity"
      "erofs"
      "gve"
      "tdx-guest"
      "configfs"
      "veth"
      "nft_masq"
      "nft_chain_nat"
      # The egress proxy's redirects and resets (phase 3).
      "nft_redir"
      "nft_reject_inet"
      # Volumes (dm-crypt AES-XTS images on loop devices, ext2 through the ext4 driver)
      # and templates (a read-only overlay over the base bundle), phase 4.
      "dm-crypt"
      "loop"
      "ext4"
      "xts"
      "aesni-intel"
      "overlay"
    ];
  });

  # The initrd. With `pinnedRootHash` (a file) it opens that root instead of the
  # command line's (image-test-wrong-roothash only).
  initrd =
    pinnedRootHash:
    pkgs.makeInitrdNG {
      name = "clovelly-initrd";
      compressor = "zstd";
      contents = [
        {
          source = ./initrd-init.sh;
          target = "/init";
        }
        {
          source = "${busybox}/bin/busybox";
          target = "/bin/busybox";
        }
        {
          source = "${kmod}/bin/modprobe";
          target = "/sbin/modprobe";
        }
        {
          source = "${cryptsetup}/bin/veritysetup";
          target = "/sbin/veritysetup";
        }
        {
          source = "${modules}/lib/modules";
          target = "/lib/modules";
        }
      ]
      ++ lib.optional (pinnedRootHash != null) {
        source = pinnedRootHash;
        target = "/etc/clovelly-pinned-roothash";
      };
    };

  # Fixed identifiers so two builds of the same inputs produce the same bytes.
  ids = {
    erofsUuid = "c4a7c0de-0000-4000-8000-000000000001";
    veritySalt = "63617274" + lib.strings.replicate 15 "00000000";
    verityUuid = "c4a7c0de-0000-4000-8000-000000000002";
    diskGuid = "c4a7c0de-0000-4000-8000-000000000003";
    espGuid = "c4a7c0de-0000-4000-8000-000000000004";
    rootGuid = "c4a7c0de-0000-4000-8000-000000000005";
    verityGuid = "c4a7c0de-0000-4000-8000-000000000006";
  };

  variants = {
    prod = {
      packages = [ ];
      console = "console=tty0 quiet";
    };
    test = {
      packages = [
        attest-tools
        pkgs.curl
      ];
      console = "console=ttyS0,115200";
    };
  };
  # A second test release: the same image under another release id.
  variantOf = v: if v == "testb" then variants.test else variants.${v};

  release = variant: if variant == "prod" then "clovelly-${version}" else "clovelly-${version}-${variant}";

  # The read-only root, its dm-verity hash tree and root hash.
  root =
    variant:
    let
      v = variantOf variant;
      bins = [
        pkgs.iproute2
        pkgs.nftables
        pkgs.chrony
        cryptsetup
        runsc
        cell-agent
        egress-proxy
      ]
      ++ v.packages;
    in
    pkgs.runCommand "clovelly-root-${variant}"
      {
        nativeBuildInputs = [
          pkgs.erofs-utils
          cryptsetup
        ];
        closure = pkgs.closureInfo {
          rootPaths = bins ++ [
            busybox
            kmod
            modules
            base-bundle
            pkgs.cacert
          ];
        };
      }
      ''
        r=$TMPDIR/root
        mkdir -p $r/{bin,sbin,etc/ssl/certs,clovelly/secureboot,proc,sys,dev,run,tmp,var,nix/store}
        xargs -a $closure/store-paths cp -a -t $r/nix/store
        for a in $(${busybox}/bin/busybox --list); do ln -s ${busybox}/bin/busybox $r/bin/$a; done
        for p in ${lib.concatStringsSep " " bins}; do
          for b in $p/bin/*; do ln -sf $b $r/bin/; done
        done
        for b in modprobe insmod rmmod lsmod; do ln -s ${kmod}/bin/$b $r/sbin/$b; done
        mkdir -p $r/lib && ln -s ${modules}/lib/modules $r/lib/modules
        ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt $r/etc/ssl/certs/ca-certificates.crt
        ln -s /run/resolv.conf $r/etc/resolv.conf
        # chronyd drops to its own user (it parses packets from the host's NTP server).
        printf 'root:x:0:0:root:/root:/bin/sh\nchrony:x:61:61:chrony:/run/chrony:/bin/false\n' > $r/etc/passwd
        printf 'root:x:0:\nchrony:x:61:\n' > $r/etc/group
        echo 'hosts: files dns' > $r/etc/nsswitch.conf
        echo '127.0.0.1 localhost' > $r/etc/hosts
        install -m755 ${./init.sh} $r/init
        install -m755 ${./udhcpc.sh} $r/etc/udhcpc.sh
        cp ${./chrony.conf} $r/etc/chrony.conf
        ln -s ${base-bundle} $r/clovelly/base-bundle
        echo ${variant} > $r/clovelly/variant
        printf '%s' ${release variant} > $r/clovelly/release
        cp ${./secureboot/db.der} $r/clovelly/secureboot/db.der
        cp ${./control-plane-ca.pem} $r/clovelly/control-plane-ca.pem

        mkdir $out
        mkfs.erofs -zlz4hc,12 -T0 --all-root --ignore-mtime -U ${ids.erofsUuid} $out/root.img $r
        veritysetup format $out/root.img $out/verity.img \
          --salt=${ids.veritySalt} --uuid=${ids.verityUuid} --root-hash-file=$out/roothash
      '';

  # An unsigned UKI for `variant`. The command line is the variant's console,
  # `clovelly.roothash=` and `panic=`. With `wrongRootHash` the command line names a root
  # hash of no root, and the initrd opens the real root from a copy baked into it.
  uki =
    {
      variant,
      name,
      panic ? "-1",
      wrongRootHash ? false,
    }:
    let
      rootfs = root variant;
      roothash = if wrongRootHash then lib.strings.replicate 64 "0" else "$(cat ${rootfs}/roothash)";
    in
    pkgs.runCommand "clovelly-uki-${name}" { nativeBuildInputs = [ pkgs.systemdUkify ]; } ''
      mkdir $out
      # No trailing newline: the agent compares the measured .cmdline with /proc/cmdline.
      printf '%s' "${(variantOf variant).console} clovelly.roothash=${roothash} panic=${panic}" > $out/cmdline
      printf 'ID=clovelly\nNAME="clovelly cell"\nVERSION_ID=${release variant}\n' > os-release
      ukify build \
        --linux=${kernel}/bzImage \
        --initrd=${initrd (if wrongRootHash then "${rootfs}/roothash" else null)}/initrd \
        --cmdline=@$out/cmdline \
        --os-release=@os-release \
        --uname=${kernel.modDirVersion} \
        --stub=${pkgs.systemdUkify}/lib/systemd/boot/efi/linuxx64.efi.stub \
        --output=$out/uki.efi
    '';

  # Signs a UKI with `key` (db, or other) from `signingKeys`. sbsign's PKCS#7 carries a
  # signing time from the clock, so it runs with the clock frozen at 1980-01-01 (Nix's
  # SOURCE_DATE_EPOCH): the signature then depends only on the key and the image.
  # `-f` freezes the clock; without it faketime only starts the clock there, and a
  # builder that takes a second longer to reach the signing call signs a later time.
  # Firmware does not check the signing time.
  sign =
    key: unsigned:
    pkgs.runCommand "${unsigned.name}-signed-${key}"
      {
        nativeBuildInputs = [
          pkgs.sbsigntool
          pkgs.libfaketime
        ];
      }
      ''
        mkdir $out
        faketime -f '1980-01-01 00:00:00' sbsign --key ${signingKeys}/${key}.key --cert ${signingKeys}/${key}.pem \
          --output $out/uki.efi ${unsigned}/uki.efi
        cp ${unsigned}/cmdline $out/cmdline
      '';

  # GPT disk: ESP with the UKI at the removable-media path, root, root verity. Sizes
  # are whole MiB and the disk is a whole GiB, as GCE image import requires.
  image =
    {
      variant,
      name,
      boot,
    }:
    let
      rootfs = root variant;
    in
    pkgs.runCommand "clovelly-image-${name}"
      {
        nativeBuildInputs = with pkgs; [
          dosfstools
          mtools
          util-linux
          gnutar
          gzip
        ];
      }
      ''
        mib() { echo $(( ($(stat -c %s "$1") + 1048575) / 1048576 )); }
        esp=128; root=$(mib ${rootfs}/root.img); verity=$(mib ${rootfs}/verity.img)
        total=$(( (1 + esp + root + verity + 1 + 1023) / 1024 * 1024 ))

        # Fixed volume id and file times (mtools stamps files from SOURCE_DATE_EPOCH).
        export SOURCE_DATE_EPOCH=0
        mkfs.vfat -C -i 43415254 -n ESP esp.img $((esp * 1024))
        mmd -i esp.img ::/EFI ::/EFI/BOOT
        mcopy -m -i esp.img ${boot}/uki.efi ::/EFI/BOOT/BOOTX64.EFI

        truncate -s ''${total}M disk.raw
        sfdisk --no-reread --no-tell-kernel disk.raw <<EOF
        label: gpt
        label-id: ${ids.diskGuid}
        start=1MiB, size=''${esp}MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=${ids.espGuid}, name=esp
        size=''${root}MiB, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=${ids.rootGuid}, name=root
        size=''${verity}MiB, type=2C7357ED-EBD2-46D9-AEC9-23F0A38F4D2B, uuid=${ids.verityGuid}, name=root-verity
        EOF
        dd if=esp.img of=disk.raw bs=1M seek=1 conv=notrunc,sparse status=none
        dd if=${rootfs}/root.img of=disk.raw bs=1M seek=$((1 + esp)) conv=notrunc,sparse status=none
        dd if=${rootfs}/verity.img of=disk.raw bs=1M seek=$((1 + esp + root)) conv=notrunc,sparse status=none

        mkdir $out
        ${measure}/bin/measure --uki ${boot}/uki.efi --disk disk.raw > $out/predicted-rtmr
        tar --format=oldgnu -S --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - disk.raw \
          | gzip -9n > $out/disk.raw.tar.gz
        echo $(( (1 + esp) * 1048576 )) > $out/root-offset
        cp ${rootfs}/roothash ${boot}/cmdline ${boot}/uki.efi $out/
        printf '%s' ${release variant} > $out/release
        sha256sum disk.raw | cut -d' ' -f1 > $out/disk.sha256
        cat > $out/versions <<EOF
        kernel=${kernel.version}
        runsc=${runsc.version}
        cell-agent=${cell-agent.version}
        egress-proxy=${egress-proxy.version}
        chrony=${pkgs.chrony.version}
        EOF
      '';

  ukiFor =
    variant:
    uki {
      inherit variant;
      name = variant;
    };
  testUki = ukiFor "test";

  # Name, version and licence of every package in the images' runtime closure, for
  # image/MANIFEST.md. Packages are found by walking the build graph of the images'
  # inputs and keeping those with an output in the closure.
  imageInputs = [
    kernel
    busybox
    kmod
    cryptsetup
    pkgs.iproute2
    pkgs.nftables
    pkgs.chrony
    python
    pkgs.cacert
    pkgs.curl
    runsc
    cell-agent
    egress-proxy
    goTdxGuest
    gcetcbendorsement
    attest-tools
    modules
    base-bundle
  ];
  # Packages built into the UKI rather than referenced from the root.
  embedded = [
    kernel
    pkgs.systemdUkify
  ];
  depsOf =
    d:
    lib.filter lib.isDerivation (
      lib.flatten (
        map (a: d.${a} or [ ]) [
          "buildInputs"
          "propagatedBuildInputs"
          "nativeBuildInputs"
          "propagatedNativeBuildInputs"
        ]
      )
    );
  graph = builtins.genericClosure {
    startSet = map (d: {
      key = d.outPath;
      drv = d;
    }) imageInputs;
    operator =
      item:
      map (d: {
        key = d.outPath;
        drv = d;
      }) (depsOf item.drv);
  };
  licence =
    p:
    lib.concatMapStringsSep " OR " (
      l: if builtins.isString l then l else l.spdxId or l.shortName or l.fullName or "unknown"
    ) (lib.toList (p.meta.license or [ ]));
  packages = map (
    i:
    let
      d = i.drv;
    in
    {
      name = d.pname or (lib.getName d);
      version = d.version or (lib.getVersion d);
      licence = licence d;
      outputs = map (o: d.${o}.outPath or d.outPath) (d.outputs or [ "out" ]);
    }
  ) graph;
  manifest =
    pkgs.runCommand "MANIFEST"
      {
        closure = pkgs.closureInfo {
          rootPaths = [
            (root "prod")
            (root "test")
            testUki
          ];
        };
        packages = builtins.toJSON packages;
        passAsFile = [ "packages" ];
        nativeBuildInputs = [ pkgs.jq ];
      }
      ''
        # The runtime closure, minus the image-assembly derivations themselves.
        grep -v -e '-clovelly-root-' -e '-clovelly-uki-' $closure/store-paths > paths
        jq -r --rawfile paths paths '
          ($paths | split("\n") | map(select(. != ""))) as $p
          | [ .[] | select(any(.outputs[]; . as $o | $p | index($o))) ]
          | unique_by(.name + .version)
          | sort_by(.name)
          | .[] | "| \(.name) | \(.version) | \(.licence) |"' $packagesPath > table
        jq -r '[ .[].outputs[] ]' $packagesPath > known
        # Paths no package claims (scripts, generated files) are listed by store name.
        while read -r p; do grep -qF "\"$p\"" known || echo "| (unattributed) \`$(basename "$p")\` | | |"; done < paths > rest
        {
          echo "| Component | Version | Licence |"
          echo "|---|---|---|"
          ${lib.concatMapStringsSep "\n" (
            p: ''echo "| ${p.pname or (lib.getName p)} (in the UKI) | ${p.version or ""} | ${licence p} |"''
          ) embedded}
          cat table rest
        } > $out
      '';
in
{
  inherit
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
    manifest
    ;
  image-prod = image {
    variant = "prod";
    name = "prod";
    boot = sign "db" (ukiFor "prod");
  };
  image-test = image {
    variant = "test";
    name = "test";
    boot = sign "db" testUki;
  };
  # What the release pipeline's two builders compare (DETERMINISM.md).
  image-prod-unsigned = image {
    variant = "prod";
    name = "prod-unsigned";
    boot = ukiFor "prod";
  };
  image-testb = image {
    variant = "testb";
    name = "testb";
    boot = sign "db" (ukiFor "testb");
  };
  image-test-altered = image {
    variant = "test";
    name = "test-altered";
    boot = sign "db" (uki {
      variant = "test";
      name = "test-altered";
      panic = "0";
    });
  };
  image-test-wrong-roothash = image {
    variant = "test";
    name = "test-wrong-roothash";
    boot = sign "db" (uki {
      variant = "test";
      name = "test-wrong-roothash";
      wrongRootHash = true;
    });
  };
  image-test-unsigned = image {
    variant = "test";
    name = "test-unsigned";
    boot = testUki;
  };
  image-test-otherkey = image {
    variant = "test";
    name = "test-otherkey";
    boot = sign "other" testUki;
  };
}
