# BF3 L7 Auth Insertion and DOCA Boundaries

This note captures the current state of L7 credential insertion for the BF3
managed-proxy work and the boundary between what belongs in software and what
belongs in BlueField dataplane offload.

## Short answer

Pure `DOCA Flow` is not the right mechanism for HTTP auth-key insertion.

The right split is:

- OVS / hardware offload on BlueField for coarse L3/L4 policy on the protected
  path
- `openshell-dpu-proxy` for TLS termination, HTTP parsing, credential
  resolution, header/query/path rewrite, and upstream forwarding

## What the current code already does

The OpenShell proxy path already implements HTTP-aware credential injection in
software.

- TLS tunnels can terminate and then call `relay_with_injected_auth(...)` in
  `crates/openshell-sandbox/src/proxy.rs`.
- Plain HTTP forward-proxy requests are rewritten in
  `rewrite_forward_request(...)`, which strips hop-by-hop proxy headers and
  rewrites header lines through `SecretResolver`.
- REST/L7 relay paths rewrite the HTTP header block before forwarding upstream.
- `openshell-dpu-proxy` is explicitly documented as a DPU-side proxy that
  terminates TLS, evaluates policy, injects credentials from a local vault
  file, and forwards traffic.

Relevant source locations:

- `crates/openshell-sandbox/src/proxy.rs:981`
- `crates/openshell-sandbox/src/proxy.rs:2122`
- `crates/openshell-sandbox/src/l7/rest.rs:274`
- `crates/openshell-sandbox/src/dpu_proxy.rs:4`

## Credential ownership is already partially separated

The codebase already distinguishes who owns the real secret material.

- `CredentialOwner::Supervisor` means the host/supervisor keeps a local
  `SecretResolver`.
- `CredentialOwner::Dpu` means the supervisor keeps placeholders only and does
  not keep a local resolver.

Relevant source locations:

- `crates/openshell-sandbox/src/secrets.rs:69`
- `crates/openshell-sandbox/src/lib.rs:360`

That means "move auth insertion off the host" and "move auth insertion into
DOCA Flow" are different questions.

The first is viable.
The second is not the right design for this stack.

## Why DOCA Flow is the wrong layer

The documented DOCA Flow feature set is packet-oriented:

- match on L2/L3/L4 and tunneled headers
- actions like forward, drop, meter, metadata, and header-field modification
- custom-header parsing over bounded header bytes

This is a good fit for coarse dataplane allow/drop/steer decisions.
It is not a good fit for full HTTP request processing.

Auth insertion requires:

1. TLS termination for HTTPS traffic
2. HTTP parsing after decryption
3. request-header or request-target rewrite
4. forwarding or re-encryption on the upstream side

Those are stream- and application-layer responsibilities. The current DOCA Flow
documentation does not present it as a generic HTTP parser or payload rewrite
engine.

Useful references:

- https://docs.nvidia.com/doca/sdk/doca-flow/index.html
- https://docs.nvidia.com/doca/sdk/doca-tls-offload-guide/index.html

## What we proved on BF3

For the current BF3 managed-proxy MVP, the protected traffic we care about is
on the OVS/representor path:

```text
guest VF -> pf0vf0 representor -> ovsbr1 -> LOCAL(10.99.2.1:3128)
```

We already proved that a high-priority OVS rule on `ovsbr1` can drop
`10.99.2.2 -> 10.99.2.1:3128` and restore it after removal.

That makes the natural dataplane ownership model:

- `policy -> DPU agent -> OVS/OpenFlow intent -> hardware offload`

not:

- `policy -> current standalone SF/VNF DOCA sample app`

## Current BF3 gap for hostless L7 injection

The DPU proxy already knows how to load `credentials.json` locally and build a
`SecretResolver` from it:

- `crates/openshell-sandbox/src/lib.rs:950`
- `crates/openshell-sandbox/src/lib.rs:978`
- `crates/openshell-sandbox/src/lib.rs:1091`
- `crates/openshell-sandbox/src/lib.rs:1115`

However, the current BF3 demo launcher starts `openshell-dpu-proxy` with
`--disable-tls-mitm`:

- `openshell-bf3-managed-proxy-demo/scripts/dpu-managed-proxy-remote.sh:187`

That means the current DPU proxy instance is running as a CONNECT tunnel for
the MVP chain, not as the L7/TLS termination owner for HTTPS traffic. In that
mode, the DPU can still own coarse allow/drop, but it cannot perform plaintext
HTTP auth insertion for encrypted upstream traffic because it never sees the
decrypted request.

So the real blocker is not DOCA Flow.
The blocker is ownership of the plaintext HTTP view.

## Recommended architecture

Near-term:

- keep coarse protected-path allow/drop in OVS / BlueField hardware offload
- move credential ownership to the DPU
- let `openshell-dpu-proxy` own TLS termination and HTTP rewrite on the DPU

That yields:

```text
policy -> DPU agent over mTLS/OOB
      -> OVS rule intent for coarse dataplane control
      -> DPU-local credentials.json + routes.yaml
      -> openshell-dpu-proxy for TLS termination and L7 auth insertion
```

Longer-term research:

- evaluate whether TLS crypto can be accelerated with BlueField TLS offload
  underneath the software proxy
- do not plan on pure DOCA Flow to perform generic HTTP auth insertion

## Next implementation steps

1. Make the BF3 launcher support a mode where the DPU proxy owns TLS MITM
   instead of always forcing `--disable-tls-mitm`.
2. Ensure the host-side component becomes a plain tunnel/client in that mode,
   not a second TLS MITM.
3. Keep provider credentials on the DPU in `credentials.json` and set
   `OPENSHELL_CREDENTIAL_OWNER=dpu` on the host side for that path.
4. Re-prove the protected path with:
   - coarse drop/allow on `ovsbr1`
   - successful header injection from the DPU proxy on a real upstream target
