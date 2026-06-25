# hash_id rules

`hash_id` is a stable rule fingerprint used for rule identity across scans, UI deep links, and future result-delta views.

## Algorithm

For each JSON rule:

```text
hash_id = SHA256(service + "|" + id + "|" + check_type + "|" + registry_path_or_powershell_check)[:12]
```

Field rules:

- `service`: logical service/category name from the rule.
- `id`: CIS rule id.
- `check_type`: checker family, such as `Registry`, `AccountPolicies`, or `UserRights`.
- `registry_path_or_powershell_check`: use `registry_path` when present; otherwise use `powershell_check`.

The first 12 hexadecimal characters are used to keep payloads compact while leaving a large collision space for the current rule volume.

## Maintenance

Generate or refresh hashes:

```powershell
python scripts/generate_hash_ids.py --rule-dir rules/CIS-WIN2025
```

Validate without writing:

```powershell
python scripts/generate_hash_ids.py --rule-dir rules/CIS-WIN2025 --check
```

Do not include mutable fields such as `title`, `expected`, `remediation`, or `reason` in the fingerprint. Those can change for wording or policy updates while the underlying rule identity remains the same.
