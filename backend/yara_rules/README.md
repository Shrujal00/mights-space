# Vendored YARA rules

## signature-base

750 rule files from [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
by Florian Roth, vendored under the **Detection Rule License (DRL) 1.1**
(`signature-base/LICENSE`). DRL 1.1 permits free use and redistribution with
attribution.

Vendored rather than fetched at run time so the tool works air-gapped, which
matters when a sample is too sensitive to take a networked machine near.

All 750 files compile and load. That depends on the external variables declared
in `app/analysis/yara_scan.py` (`filename`, `filepath`, `extension`, `filetype`,
`owner`) — a large share of these rules reference them, and YARA rejects any
rule file naming an undeclared identifier. Without those declarations 13 files
silently drop out of the ruleset.

### Updating

```bash
git clone --depth 1 https://github.com/Neo23x0/signature-base.git /tmp/sb
cp /tmp/sb/yara/*.yar /tmp/sb/yara/*.yara backend/yara_rules/signature-base/
cp /tmp/sb/LICENSE backend/yara_rules/signature-base/LICENSE
```

Then confirm nothing regressed:

```bash
cd backend && .venv/bin/python -c "
from app.analysis.yara_scan import YaraScanner
s = YaraScanner('yara_rules')
print('loaded', s.loaded_files, 'skipped', len(s.skipped_files))
for name, err in s.skipped_files: print(' ', name, err[:70])
"
```

A handful of skipped files is survivable — the scanner isolates each file so one
bad rule cannot take down the ruleset — but a sudden jump in skips usually means
a new external variable or a module (`cuckoo`, `magic`) this build lacks.
