import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib
import uuid

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def host_triple():
    for line in run(["rustc", "-vV"], cwd="core").splitlines():
        if line.startswith("host: "):
            return line.split(" ", 1)[1]
    raise SystemExit("sbom: cannot determine host triple")


def cargo_components(cargo, flags):
    meta = json.loads(run([cargo, "metadata", "--frozen", "--offline", "--format-version", "1",
                           "--manifest-path", "crates/kms-core/Cargo.toml",
                           "--filter-platform", host_triple(), *flags], cwd="core"))
    lock = tomllib.loads(pathlib.Path("core/Cargo.lock").read_text())
    checksums = {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = next(pid for pid in meta["workspace_members"] if packages[pid]["name"] == "kms-core")

    def walk(start, kinds):
        seen, stack = set(), [start]
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            for d in nodes[pid]["deps"]:
                if any(k["kind"] in kinds for k in d["dep_kinds"]):
                    stack.append(d["pkg"])
        return seen

    runtime = walk(root, {None})
    build = set()
    for pid in runtime:
        for d in nodes[pid]["deps"]:
            if any(k["kind"] == "build" for k in d["dep_kinds"]):
                build |= walk(d["pkg"], {None, "build"})
    build -= runtime

    def ref(pid):
        p = packages[pid]
        if p["source"] == CRATES_IO:
            return f"pkg:cargo/{p['name']}@{p['version']}"
        return f"pkg:generic/pairier/{p['name']}@{p['version']}"

    components, deps = [], []
    for pid in sorted(runtime | build, key=ref):
        p = packages[pid]
        c = {"type": "application" if pid == root else "library", "bom-ref": ref(pid), "name": p["name"], "version": p["version"]}
        if p["source"] == CRATES_IO:
            c["purl"] = ref(pid)
            sha = checksums.get((p["name"], p["version"]))
            if sha:
                c["hashes"] = [{"alg": "SHA-256", "content": sha}]
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"]}]
        if pid in build:
            c["scope"] = "excluded"
            c["properties"] = [{"name": "pairier:role", "value": "build-only"}]
        components.append(c)
        kinds = {None} if pid in runtime else {None, "build"}
        on = sorted({ref(d["pkg"]) for d in nodes[pid]["deps"] if any(k["kind"] in kinds or k["kind"] == "build" for k in d["dep_kinds"]) and d["pkg"] in runtime | build})
        deps.append({"ref": ref(pid), "dependsOn": on})
    return ref(root), components, deps


def go_components(binaries, version):
    components, deps, refs = [], [], []
    go_version, fips = None, None
    for b in binaries:
        info = run(["go", "version", "-m", b])
        lines = info.splitlines()
        go_version = lines[0].split(": ", 1)[1].strip()
        name = pathlib.Path(b).name
        r = f"pkg:golang/github.com/Quant-Off/pairier/host/cmd/{name}@{version}"
        props = []
        for line in lines[1:]:
            parts = line.strip().split("\t")
            if parts[0] == "build" and len(parts) > 1 and "=" in parts[1]:
                k, v = parts[1].split("=", 1)
                if k in ("GOFIPS140", "DefaultGODEBUG", "CGO_ENABLED", "GOOS", "GOARCH", "vcs.revision"):
                    props.append({"name": f"go:build:{k}", "value": v})
                if k == "GOFIPS140":
                    fips = v
            if parts[0] == "dep":
                raise SystemExit(f"sbom: unexpected go dependency in {b}: {line}")
        components.append({"type": "application", "bom-ref": r, "name": name, "version": version, "purl": r, "properties": sorted(props, key=lambda p: p["name"])})
        refs.append(r)
    std = f"pkg:golang/stdlib@{go_version.removeprefix('go')}"
    components.append({"type": "library", "bom-ref": std, "name": "go-stdlib", "version": go_version.removeprefix("go"), "purl": std, "licenses": [{"expression": "BSD-3-Clause"}]})
    on = [std]
    if fips and fips != "off":
        fr = f"pkg:generic/go/crypto-internal-fips140@{fips}"
        components.append({"type": "library", "bom-ref": fr, "name": "go-cryptographic-module", "version": fips, "licenses": [{"expression": "BSD-3-Clause"}],
                           "properties": [{"name": "fips:standard", "value": "FIPS 140-3"}]})
        on.append(fr)
    for r in refs:
        deps.append({"ref": r, "dependsOn": sorted(on)})
    return refs, components, deps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--cargo", default="cargo")
    ap.add_argument("--core-flags", default="")
    ap.add_argument("--go-binary", action="append", default=[])
    ap.add_argument("--epoch", type=int, default=0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    core_ref, cc, cd = cargo_components(a.cargo, a.core_flags.split())
    go_refs, gc, gd = go_components(a.go_binary, a.version)
    top = f"pkg:generic/pairier@{a.version}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.fromtimestamp(a.epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "bom-ref": top, "name": "pairier", "version": a.version},
            "properties": [{"name": "pairier:core-flags", "value": a.core_flags.strip()}],
        },
        "components": sorted(cc + gc, key=lambda c: c["bom-ref"]),
        "dependencies": sorted([{"ref": top, "dependsOn": sorted([core_ref, *go_refs])}] + cd + gd, key=lambda d: d["ref"]),
    }
    body = json.dumps(bom, sort_keys=True, separators=(",", ":")).encode()
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(body).hexdigest()))
    pathlib.Path(a.out).write_text(json.dumps(bom, sort_keys=True, indent=2) + "\n")
    print(a.out)


if __name__ == "__main__":
    sys.exit(main())
