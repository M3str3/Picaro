# Measurement template

Use this template for each test against a real EDR. Copy it to
`docs/measurements/<edr-name>.md` and fill every field.

```markdown
# <EDR name> — <technique name>

## EDR

- Product: <name>
- Version: <version>
- Configuration: <default / ASR rules / custom policy>

## Technique

- Name: <technique>
- ATT&CK: <id>

## Config (YAML used)

<yaml block>

## Result

- [ ] Blocked
- [ ] Allowed
- [ ] Partial

## Where it was blocked (if known)

- <e.g. static scan, runtime API hook, ETW-TI, kernel callback, ...>

## Evidence

- Screenshot: <path>
- Log: <path>

## Date

- <YYYY-MM-DD>
```
