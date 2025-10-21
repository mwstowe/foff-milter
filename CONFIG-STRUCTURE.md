# FOFF Milter Configuration Structure

## Overview
The configuration system uses a 3-tier approach for maximum flexibility and clarity.

## 1. Main TOML Configuration
**File:** `/etc/foff-milter.toml` (production) or `foff-milter.toml` (development)

```toml
[system]
socket_path = "/var/run/foff-milter.sock"

[modules]
enabled = true
config_dir = "/etc/foff-milter/modules"

[legacy]
enabled = false
config_file = "/etc/foff-milter/legacy-rules.yaml"

[statistics]
enabled = true
database_path = "/var/lib/foff-milter/stats.db"
flush_interval_seconds = 60

[default_action]
type = "Accept"
```

## 2. Module Configuration Directory
**Directory:** `/etc/foff-milter/modules/` (production) or `modules/` (development)

Each module has its own YAML file:

### `/etc/foff-milter/modules/suspicious-domains.yaml`
```yaml
name: "Suspicious Domains"
enabled: true
rules:
  - name: "Tag suspicious TLD domains"
    criteria:
      type: "SenderPattern"
      pattern: ".*@.*\\.(tk|ml|ga|cf)$"
    action:
      type: "TagAsSpam"
      header_name: "X-Spam-Flag"
      header_value: "YES"
```

### `/etc/foff-milter/modules/brand-impersonation.yaml`
```yaml
name: "Brand Impersonation Protection"
enabled: true
rules:
  - name: "DocuSign phishing detection"
    criteria:
      type: "And"
      criteria:
        - type: "SubjectPattern"
          pattern: "(?i).*(docusign|document.*ready).*"
        - type: "Not"
          criteria:
            type: "SenderPattern"
            pattern: ".*@docusign\\.com$"
    action:
      type: "TagAsSpam"
      header_name: "X-Spam-Flag"
      header_value: "YES"
```

## 3. Legacy Configuration (Optional)
**File:** `/etc/foff-milter/legacy-rules.yaml` (only if `[legacy] enabled = true`)

```yaml
socket_path: "/var/run/foff-milter.sock"
rules:
  - name: "Legacy spam pattern"
    criteria:
      type: "SubjectPattern"
      pattern: "(?i).*(viagra|cialis).*"
    action:
      type: "Reject"
      message: "Rejected by legacy rule"
default_action:
  type: "Accept"
```

## Configuration Hierarchy

1. **Main TOML** → Points to module directory and legacy config
2. **Module Directory** → Contains individual module configurations
3. **Legacy Config** → Optional backward compatibility

## Benefits

- **Clear separation**: Each module has its own file
- **Easy maintenance**: Add/remove modules by adding/removing files
- **Flexible deployment**: Enable/disable modules or legacy system
- **Production ready**: Clean `/etc` structure
- **Development friendly**: Local relative paths for testing

## Deployment Strategy

### Production
```
/etc/foff-milter.toml              # Main config
/etc/foff-milter/modules/          # Module directory
├── suspicious-domains.yaml
├── brand-impersonation.yaml
├── health-spam.yaml
└── ...
/etc/foff-milter/legacy-rules.yaml # Optional legacy
```

### Development
```
foff-milter.toml                   # Main config
modules/                           # Module directory
├── suspicious-domains.yaml
├── brand-impersonation.yaml
└── ...
legacy-rules.yaml                  # Optional legacy
```
