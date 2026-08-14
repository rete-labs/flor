# Security

Apply these constraints to SPIFFE/SVID, mTLS, identity mapping, certificates, trust domains, authorization, secrets, and cryptographic behavior:

- Parse and validate SPIFFE IDs with the `spiffe` crate rather than ad hoc string rules.
- Keep trust domains explicit and unambiguous across inputs.
- Treat URI SAN as the identity carrier; do not treat CN as identity.
- Reject mismatched or multiple unexpected identities in CSR and certificate flows.
- Preserve Florete identity semantics when mapping kind and scope.
- Verify peer identity, certificate chain, trust domain, and intended role in mTLS paths.
- Keep insecure verifiers and unauthenticated paths test-only, clearly isolated, or explicitly documented.
- Do not log secrets, private keys, unnecessary certificate material, or sensitive identities.
- Keep errors useful without exposing sensitive material.
- Keep crypto backend and dependency choices compatible with the existing Rustls, Quinn, and ring stack.
