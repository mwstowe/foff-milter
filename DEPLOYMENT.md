# FOFF Milter Deployment Scripts

This directory contains deployment scripts for automatically deploying the FOFF milter to FreeBSD and AlmaLinux systems.

## Scripts

### `deploy.sh` - Basic Deployment Script
A straightforward deployment script that handles the core functionality.

**Features:**
- Host reachability checks
- VirtualBox VM management
- Sequential deployment
- Basic error handling
- Colored output

**Usage:**
```bash
# Deploy to both systems
./deploy.sh

# Deploy to FreeBSD only
./deploy.sh --freebsd-only

# Deploy to AlmaLinux only
./deploy.sh --almalinux-only

# Show help
./deploy.sh --help
```

### `deploy_advanced.sh` - Advanced Deployment Script
An enhanced version with additional features for production use.

**Features:**
- Comprehensive logging with timestamps
- SSH connectivity verification
- System information gathering
- Deployment script validation
- Parallel deployment option
- Debug mode
- Performance timing
- Detailed error reporting

**Usage:**
```bash
# Deploy to both systems (sequential)
./deploy_advanced.sh

# Deploy to both systems in parallel
./deploy_advanced.sh --parallel

# Deploy with debug logging
./deploy_advanced.sh --debug

# Deploy to FreeBSD only
./deploy_advanced.sh --freebsd-only

# Deploy to AlmaLinux only
./deploy_advanced.sh --almalinux-only

# Show help
./deploy_advanced.sh --help
```

**Environment Variables:**
```bash
# Enable debug mode
DEBUG=1 ./deploy_advanced.sh

# Enable parallel deployment
PARALLEL=1 ./deploy_advanced.sh
```

## Target Systems

### FreeBSD System
- **Hostname:** `vegapunk.johnson.home`
- **VirtualBox VM:** `vegapunk`
- **Deployment Script:** `/usr/tools/deploy_foff.sh`

### AlmaLinux System
- **Hostname:** `almalinux.johnson.home`
- **VirtualBox VM:** `almalinux`
- **Deployment Script:** `/usr/tools/deploy_foff.sh`

## Prerequisites

### Local System Requirements
- **VirtualBox:** Must be installed with `VBoxManage` command available
- **SSH Access:** Passwordless SSH access to both target systems as root
- **Network:** Target systems must be reachable when running

### Target System Requirements
- **Deployment Script:** `/usr/tools/deploy_foff.sh` must exist and be executable
- **SSH Server:** Must be running and accessible
- **Root Access:** SSH access as root user required

## Deployment Process

The scripts follow this process for each target system:

1. **Connectivity Check**
   - Ping the target hostname
   - If unreachable, proceed to VM startup

2. **VM Management** (if needed)
   - Identify the VirtualBox VM name
   - Check current VM state
   - Start/resume the VM if necessary
   - Wait for the system to become reachable

3. **Pre-deployment Validation**
   - Verify SSH connectivity
   - Check deployment script exists and is executable
   - Gather system information (advanced script only)

4. **Deployment Execution**
   - Execute `/usr/tools/deploy_foff.sh` on the target system
   - Monitor output and capture logs
   - Report success/failure status

5. **Summary Report**
   - Display deployment results for all systems
   - Show timing information
   - Provide log file locations

## Logging

### Basic Script (`deploy.sh`)
- Console output with colored status messages
- No persistent logging

### Advanced Script (`deploy_advanced.sh`)
- **Main Log:** `./deployment_logs/deploy_YYYYMMDD_HHMMSS.log`
- **System Logs:** `./deployment_logs/freebsd_YYYYMMDD_HHMMSS.log`
- **System Logs:** `./deployment_logs/almalinux_YYYYMMDD_HHMMSS.log`
- Timestamped entries with log levels
- Console output with colored status messages

## Error Handling

Both scripts include comprehensive error handling:

- **Network Issues:** Automatic VM startup if hosts are unreachable
- **VM Problems:** Detailed VM state checking and management
- **SSH Issues:** Connection timeout and retry logic
- **Deployment Failures:** Clear error messages and exit codes
- **Missing Dependencies:** Validation of required tools and scripts

## Troubleshooting

### Common Issues

1. **VBoxManage not found**
   - Install VirtualBox or add to PATH
   - Verify VirtualBox installation

2. **VM not found**
   - Check VM names in VirtualBox
   - Ensure VMs are properly configured

3. **SSH connection failed**
   - Verify SSH keys are set up
   - Check SSH service on target systems
   - Confirm root access is enabled

4. **Deployment script not found**
   - Ensure `/usr/tools/deploy_foff.sh` exists on target systems
   - Verify script permissions (executable)

5. **Host unreachable after VM start**
   - Check VM network configuration
   - Verify VM is fully booted
   - Check firewall settings

### Debug Mode

Use the advanced script with debug mode for detailed troubleshooting:

```bash
DEBUG=1 ./deploy_advanced.sh --debug
```

This provides additional logging including:
- Detailed ping and SSH attempts
- VirtualBox command output
- System information gathering
- Step-by-step process tracking

## Security Considerations

- **SSH Keys:** Use SSH key authentication instead of passwords
- **Root Access:** Limit root SSH access to deployment systems only
- **Network Security:** Ensure target systems are on trusted networks
- **Log Security:** Protect deployment logs as they may contain sensitive information

## Integration

These scripts can be integrated into CI/CD pipelines or automated deployment systems:

```bash
# Example CI/CD integration
if ./deploy_advanced.sh --parallel; then
    echo "Deployment successful"
    # Continue with post-deployment tasks
else
    echo "Deployment failed"
    exit 1
fi
```

## Support

For issues with the deployment scripts:
1. Check the troubleshooting section above
2. Review log files in `./deployment_logs/`
3. Run with debug mode for detailed information
4. Verify all prerequisites are met
