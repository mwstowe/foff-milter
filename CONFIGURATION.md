# Configuration Management Guide

This guide explains how to separate environment-specific configuration from the main rule set for better maintainability and portability.

## Current Approach

The milter currently uses a single YAML configuration file (`hotel.yaml`) that contains both universal rules and environment-specific settings.

## Recommended Separation Strategy

### 1. Environment-Specific Items to Extract

**Whitelist Rules:**
- Trusted Gmail senders: `patoertel39@gmail.com`
- Trusted business contacts
- Organization-specific email addresses

**Domain-Specific Rules:**
- SparkPost blocking for specific recipients: `queued@example.com`
- Internal domain patterns
- Organization-specific blocking rules

**Environment Settings:**
- Socket paths
- Database paths
- SMTP configuration

### 2. Recommended File Structure

```
/etc/foff-milter/
├── rules-base.yaml          # Universal spam detection rules
├── whitelist-production.yaml   # Production whitelists
├── whitelist-staging.yaml      # Staging whitelists
└── environment.yaml            # Environment-specific settings
```

### 3. Example Whitelist Configuration

Create `whitelist-production.yaml`:

```yaml
# Production whitelist configuration
rules:
  # Trusted Gmail senders
  - name: "Whitelist trusted Gmail sender john.doe"
    criteria:
      type: "SenderPattern"
      pattern: "john\\.doe@gmail\\.com"
    action:
      type: "Accept"

  - name: "Whitelist trusted Gmail sender jane.smith"
    criteria:
      type: "SenderPattern"
      pattern: "jane\\.smith@gmail\\.com"
    action:
      type: "Accept"

  # Trusted business partners
  - name: "Whitelist business partner"
    criteria:
      type: "SenderPattern"
      pattern: ".*@trusted-partner\\.com$"
    action:
      type: "Accept"

  # Organization-specific rules
  - name: "Block SparkPost to internal queue"
    criteria:
      type: "And"
      criteria:
        - type: "SenderPattern"
          pattern: ".*\\.sparkpostmail\\.com"
        - type: "RecipientPattern"
          pattern: "queue@yourcompany\\.com"
    action:
      type: "Reject"
      message: "SparkPost blocked for internal queue"
```

### 4. Implementation Options

#### Option A: Manual Merge (Current Recommendation)

1. **Create base rules file** with universal spam detection rules
2. **Create environment-specific whitelist files**
3. **Manually merge** before deployment using YAML tools or scripts

```bash
# Example merge script
yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' \
  rules-base.yaml whitelist-production.yaml > hotel.yaml
```

#### Option B: Multi-File Loading (Future Enhancement)

Add support for loading multiple configuration files:

```bash
./foff-milter -c rules-base.yaml -w whitelist-production.yaml
```

#### Option C: Environment Variables

Use environment variable substitution in YAML:

```yaml
- name: "Whitelist trusted Gmail sender"
  criteria:
    type: "SenderPattern"
    pattern: "${TRUSTED_GMAIL_SENDER}"
  action:
    type: "Accept"
```

### 5. Migration Steps

1. **Identify environment-specific rules** in current `hotel.yaml`
2. **Extract whitelist rules** to separate file
3. **Extract organization-specific patterns** 
4. **Create base rules file** with universal detection rules
5. **Set up merge process** for deployment
6. **Test merged configuration** thoroughly

### 6. Benefits

✅ **Portability**: Base rules can be shared across environments  
✅ **Security**: Sensitive whitelists kept separate  
✅ **Maintainability**: Universal rules updated independently  
✅ **Flexibility**: Different whitelists per environment  
✅ **Version Control**: Separate change tracking  

### 7. Environment-Specific Examples

**Production Whitelist:**
- Executive email addresses
- Critical business partners
- Automated systems

**Staging Whitelist:**
- Test accounts
- Developer email addresses
- QA automation senders

**Development Whitelist:**
- All internal developers
- Test email services
- Debugging accounts

### 8. Security Considerations

- **Restrict access** to whitelist files (sensitive business relationships)
- **Audit whitelist changes** (who gets special treatment)
- **Regular review** of whitelisted senders (remove outdated entries)
- **Separate credentials** for different environments

This approach provides flexibility while maintaining the current single-file simplicity until multi-file loading is implemented.
