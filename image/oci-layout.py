#!/usr/bin/env python3
"""Turns a docker-archive from dockerTools.buildLayeredImage into an OCI image layout whose
manifest digest depends only on the image's contents: the digest a release logs and a rebuild
reproduces. `docker push` would compress the layers again, with whatever it has, so the layers
are compressed here, with the pinned zlib and no timestamp, and pushed as they are.

    oci-layout.py IMAGE.tar.gz OUT

Writes OUT/oci-layout, OUT/index.json, OUT/blobs/sha256/* and OUT/digest (sha256:<hex> of the
manifest, which is what `skopeo copy --preserve-digests` publishes).
"""
import gzip
import hashlib
import json
import os
import sys
import tarfile

SOURCE = "https://github.com/clovelly-io/clovelly"


def main(archive, out):
    blobs = os.path.join(out, "blobs", "sha256")
    os.makedirs(blobs)

    def put(data):
        digest = hashlib.sha256(data).hexdigest()
        with open(os.path.join(blobs, digest), "wb") as f:
            f.write(data)
        return {"digest": f"sha256:{digest}", "size": len(data)}

    with tarfile.open(archive, "r:*") as tar:
        read = lambda name: tar.extractfile(name).read()
        entry = json.loads(read("manifest.json"))[0]
        config = put(read(entry["Config"]))
        layers = []
        for name in entry["Layers"]:
            layer = read(name)
            if layer[:2] != b"\x1f\x8b":
                layer = gzip.compress(layer, compresslevel=6, mtime=0)
            layers.append(put(layer))

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **l} for l in layers],
        "annotations": {"org.opencontainers.image.source": SOURCE},
    }
    described = put(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode())
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"mediaType": manifest["mediaType"], **described}],
    }
    with open(os.path.join(out, "index.json"), "w") as f:
        json.dump(index, f, separators=(",", ":"), sort_keys=True)
    with open(os.path.join(out, "oci-layout"), "w") as f:
        f.write('{"imageLayoutVersion":"1.0.0"}')
    with open(os.path.join(out, "digest"), "w") as f:
        f.write(described["digest"] + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
