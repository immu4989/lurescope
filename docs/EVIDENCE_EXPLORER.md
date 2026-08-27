# Browser Evidence Explorer

The [GitHub Pages lab](https://immu4989.github.io/lurescope/) can open operational
evidence locally in the browser. Choose **Evidence JSON** near the bottom of the
page to inspect:

- LureEval source receipts and compatible aggregates;
- Pilot Gate and Shadow Inbox reports;
- offline Microsoft Defender paired reports;
- LureProof statements and DSSE envelopes; and
- combined SCuBA assurance and drift-ledger statements; and
- LureWatch aggregate entries and in-toto checkpoint/DSSE artifacts.

The file is bounded to 8 MiB, read with the browser File API, parsed in the tab,
and never sent to the LureScope API or another origin. The explorer shows the
artifact type, decision state, core metrics, SHA-256 byte bindings, privacy
exclusions, and machine-readable limitations.

This is an explanation surface, not the normative verifier. It performs bounded
shape inspection and decodes an in-toto DSSE payload, but it does not accept a
public key or authenticate the signature. A badge saying “signature present”
means only that an envelope carries signature bytes. Use the corresponding CLI
verification command and a trusted public key before relying on issuer identity
or semantic validity.

For LureWatch, browser inspection also does not recompute the e-process, fixed
family correction, or predecessor chain. Use `lurescope monitor verify` for the
normative statistical and integrity check.
