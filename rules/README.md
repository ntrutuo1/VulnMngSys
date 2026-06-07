# Rules Structure

`rules/` is organized by benchmark profile folder.

Profile folders should use stable names:

- `CIS-WIN2022`
- `CIS-WIN2022_STANDARD`
- `CIS-WIN2022-STIG`
- `CIS-WIN2019-AZURE`
- `CIS-WIN2012_R2`
- `CIS-WIN2012_nonR2`

Each populated profile folder can contain JSON rule files directly. A separate
manifest is optional. When no manifest exists, the scanner builds one
automatically:

- quick scan: first `_1.json` file, or the first sorted JSON file
- full scan: all JSON files in the selected profile folder

Auto-fit behavior:

- The inventory script emits a Windows Server profile hint from OS caption.
- `VULNMNGSYS_RULE_PROFILE` can override the profile at runtime.
- The catalog selects the closest populated benchmark folder.
- Empty benchmark folders are ignored until JSON files are added.
- `common/` is shared metadata only and is never selected as a scan profile.
- If the exact version is missing, the nearest populated Windows Server year is
  used as a fallback.

Keep generated reports and build outputs outside this folder.
