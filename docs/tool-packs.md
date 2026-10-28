# Tool packs: one way to ship every tool

A **tool pack** is the unit in which tools are versioned, built, signed and delivered to sensors. Our own tools and
tools written by anyone else use the same format and the same contract:

- each tool is a `tool.yaml` plus its program ([adapter-protocol.md](adapter-protocol.md), the tool contract v1);
- a pack is a directory with a `pack.yaml` and one or more tools;
- a first-party pack is built into a sensor profile image; any pack can also be built into its own OCI image that a
  sensor runs per job in its sandbox.

The author writes the tool's logic. Everything around it is the runtime's job and is never in the pack: scheduling,
scope enforcement (the sensor refuses an out-of-scope target whatever the tool does), the sandbox, resource limits,
egress and proxies, retries, credential delivery, output checks, deduplication, provenance ("found by tool X vN"),
logs and delivery to the platform.

Schema: [`pkg/tool/schema/pack.v1.schema.json`](../pkg/tool/schema/pack.v1.schema.json). Go: `pkg/tool/pack`.
Example: [`examples/packs/http-title`](../examples/packs/http-title), a Python tool for `probe.http@1`.

## Layout

```
my-pack/
  pack.yaml
  my-tool/            # one directory per tool (tools[].path, default: the tool's name)
    tool.yaml
    my_tool.py
    fixtures/...
```

A pack of one tool may keep `tool.yaml` next to `pack.yaml` (`path: .`); `openctem tool init` writes that layout.
Tool paths are relative, stay inside the pack directory and may not pass through a symbolic link.

## pack.yaml

```yaml
apiVersion: openctem.io/pack/v1
name: http-title                 # ^[a-z][a-z0-9-]{1,62}$
version: 0.1.0                   # semantic version, no leading v; any change to the pack's files needs a new one
description: Status code, server header and title of HTTP services.
publisher: example               # your namespace; a catalog binds it to your signing identity
license: Apache-2.0              # SPDX expression of the pack's own files
tier: T1                         # T0 passive, T1 active, T2 intrusive: checked, see below
tools:
  - name: http-title
    path: .
engines:                         # every program a tool runs as its engine (tool.yaml engine.name)
  - name: httpx
    version: 1.12.0
    license: MIT
    url: https://downloads.example.com/httpx/1.12.0/httpx.zip
    sha256:                      # when set, one per platform of the pack
      linux/amd64: 9d8439e8...
      linux/arm64: fd7b123c...
platforms: [linux/amd64, linux/arm64]
requires:
  sdk: 0.39.0                    # the oldest sensor SDK that runs the pack
  protocol: 1                    # adapter protocol major
image:                           # a pack built into its own image (absent for a profile-only pack)
  base: public.ecr.aws/docker/library/python:3.12-slim@sha256:a6e34c59...   # pinned by digest
```

`pack.yaml` holds only what no `tool.yaml` can say. Capabilities, inputs and outputs, the configuration schema (which
the console renders as the tool's settings form), credentials, network needs, resources and safety stay in each
tool's `tool.yaml`; `openctem tool describe <pack>` prints the pack view derived from them.

### Rules the loader enforces

| Rule | Why |
|---|---|
| Unknown keys, duplicate keys and a second YAML document are errors | `pack.yaml` is a security document |
| `tier` equals the highest minimum tier of the pack's tools (declared tier, capability tier floors, `T2` for a declared side effect) | a reader sees the truth, and a pack cannot label an active tool passive (or claim more than it does) |
| The tools are exactly the ones `tools` lists, by name | nothing travels in a pack unlisted |
| Every engine a tool names is in `engines` | the bundled programs are an inventory you can review, license-check and pin |
| A pinned engine has a sha256 for every platform | a build on another architecture cannot fall back to an unpinned download |
| `requires.sdk` is at least every tool's `sdk.min`, and not newer than the SDK reading it | a sensor refuses with "needs SDK X; this is Y", never with an unknown-key error |
| `requires.protocol` is a protocol every tool speaks (1) | |
| `image.base` is pinned by digest | a moving tag would change a signed pack |
| Platforms are `linux/amd64` and `linux/arm64` | |

## Tier and profiles

Tiers are the capability taxonomy's: **T0** passive (reads, never sends a packet to a target), **T1** active and not
intrusive, **T2** intrusive. The tier of a tool is the highest of its declared tier and the tier floors of the
capabilities it implements; the platform may assign a higher one, never a lower one. The tier of a pack is the
highest tier of its tools.

The sensor's profile images are built from first-party packs by tier: the passive profile holds only T0 packs, so it
contains no program that can actively touch a target.

## Commands

| Command | On a pack directory |
|---|---|
| `openctem tool init --kind python --capability probe.http@1 --name my-tool dir` | writes a tool and its one-tool `pack.yaml` |
| `openctem tool validate dir` | validates `pack.yaml`, every tool and the rules above |
| `openctem tool test dir [--capability] [--scope] [--fuzz 30s]` | runs the conformance kit on every tool |
| `openctem tool describe [--json] dir` | prints the pack view: tier, capabilities, credentials, network, engines, tool digests |
| `openctem tool build dir (--output oci-dir \| --push repo:tag) [--platform ...] [--base name@sha256:...]` | builds the pack image (below) and prints its digest |

A directory with a `pack.yaml` is a pack for every command; name the `tool.yaml` file to work on one tool.

## The pack image

`openctem tool build` makes a multi-platform OCI image without a container daemon:

- for each platform of the pack, the base image's manifest for that platform plus **one layer** holding the pack
  directory at `/opt/openctem/pack` (`pack.yaml` at `/opt/openctem/pack/pack.yaml`);
- files under `.build/<os>-<arch>/` (for example a compiled program per architecture) replace or add files at the same
  paths in that platform's layer; `.build` itself, `.git` and `__pycache__` never enter the image;
- only regular files and directories are packed: a symbolic link or special file anywhere in the pack fails the build;
  at most 10,000 files and 512 MiB;
- the layer is reproducible (sorted entries, owned by root, no timestamps, modes 0644 or 0755), the image has no
  creation time, no entrypoint or command (the sensor starts each tool from its `tool.yaml`), runs as user
  65532, and carries the labels `io.openctem.pack.name`, `.version`, `.publisher`, `.tier` and `.digest` (the
  `pack.yaml` digest, which a sensor checks against the file it finds); the index carries the same annotations.

The same pack and base always give the same index digest. That digest is what you sign, what a catalog lists and what
a job pins: never a tag.

## Sign and publish

The CI templates ([GitHub](../ci/github/openctem-tool.yml), [GitLab](../ci/gitlab/openctem-tool.yml)) run the checks
on every change and, on a tag `vX.Y.Z` equal to the pack version, build and push the pack image and sign its digest
keylessly with cosign (Sigstore) under the CI job's own identity. No key to manage: the signature names the
repository and workflow that built the image, and that identity is what a tenant pins when it registers the pack.

## Versioning

- `apiVersion: openctem.io/pack/v1` only grows by optional keys. A new key needs an SDK that knows it, which
  `requires.sdk` states.
- A pack version is immutable: the same name and version with other content is refused by a catalog.
- A tool's version follows `openctem tool diff`; a pack's version moves whenever any of its files changes, by at least
  the largest bump of its tools.
- A sensor and a pack are released independently: the sensor checks `requires` and the tools' protocol range, the
  platform checks compatibility from what the sensor reports, and neither needs the other's release.
