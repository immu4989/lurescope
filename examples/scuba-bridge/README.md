# Synthetic ScubaGear bridge fixture

`ScubaResults_synthetic.json` is a deliberately small, fully synthetic imitation of
the public ScubaGear 1.8.0 consolidated report contract. It contains no real tenant,
domain, account, user, configuration, finding, or remediation data.

The fixture exercises AAD, Microsoft 365 Defender, and Exchange Online with five
controls: two passes, two failing `Shall` controls, and one warning. Its raw settings,
tenant fields, requirements, details, comment, and remediation date contain distinctive
sentinel text. Tests fail if any of that text enters the minimized bridge output.

Reviewed SHA-256:

```text
6e3cdb81378ab6b4d3c2a0ee0df1acb8a607a23ac223cc498165f27d536e64b9
```

This fixture verifies software behavior only. It is not a CISA-produced report,
deployment evidence, a baseline assessment, a finding, or a recommended POA&M.
The strict importer has also been exercised during development against CISA's public
[`ScubaResults_fa5589b7-d528-4f80.json`](https://github.com/cisagov/ScubaGear/blob/v1.8.0/PowerShell/ScubaGear/Sample-Reports/ScubaResults_fa5589b7-d528-4f80.json)
sample (retrieved 2026-08-19; SHA-256
`8746a9ea9142d04ed80f957bf6cdc57e950da6fa9def1b1f16b79886311dee64`). That
much larger upstream artifact is not copied into this repository.
