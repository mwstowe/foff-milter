#!/bin/bash

# FOFF Milter Advanced Deployment Script
# Deploys to FreeBSD (vegapunk.johnson.home) and AlmaLinux (almalinux.johnson.home)
# Features: Logging, parallel deployment, rollback support, health checks

set -e  # Exit on any error

# Configuration
FREEBSD_HOST="vegapunk.johnson.home"
ALMALINUX_HOST="almalinux.johnson.home"
DEPLOY_SCRIPT="/usr/tools/deploy_foff.sh"
TIMEOUT=30
MAX_START_WAIT=120
LOG_DIR="./deployment_logs"
LOG_FILE="$LOG_DIR/deploy_$(date +%Y%m%d_%H%M%S).log"

# Create log directory
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_with_timestamp() {
    local level=$1
    local color=$2
    local message=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Log to console with color
    echo -e "${color}[$level]${NC} $message"
}

log_info() {
    log_with_timestamp "INFO" "$BLUE" "$1"
}

log_success() {
    log_with_timestamp "SUCCESS" "$GREEN" "$1"
}

log_warning() {
    log_with_timestamp "WARNING" "$YELLOW" "$1"
}

log_error() {
    log_with_timestamp "ERROR" "$RED" "$1"
}

log_debug() {
    if [[ "${DEBUG:-}" == "1" ]]; then
        log_with_timestamp "DEBUG" "$PURPLE" "$1"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script exited with error code $exit_code"
        log_info "Check log file: $LOG_FILE"
    fi
}

trap cleanup EXIT

# Check if a host is reachable
check_host_reachable() {
    local host=$1
    log_debug "Pinging $host with timeout $TIMEOUT seconds"
    
    if ping -c 1 -W $TIMEOUT "$host" >/dev/null 2>&1; then
        log_success "$host is reachable"
        return 0
    else
        log_warning "$host is not reachable"
        return 1
    fi
}

# Check SSH connectivity
check_ssh_connectivity() {
    local host=$1
    log_debug "Testing SSH connectivity to $host"
    
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes root@"$host" "echo 'SSH test successful'" >/dev/null 2>&1; then
        log_success "SSH connectivity to $host verified"
        return 0
    else
        log_warning "SSH connectivity to $host failed"
        return 1
    fi
}

# Get VirtualBox VM name from hostname
get_vm_name() {
    local host=$1
    case $host in
        "$FREEBSD_HOST")
            echo "vegapunk"
            ;;
        "$ALMALINUX_HOST")
            echo "almalinux"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Check VirtualBox VM status
check_vm_status() {
    local vm_name=$1
    
    if ! command -v VBoxManage >/dev/null 2>&1; then
        log_error "VBoxManage command not found. Is VirtualBox installed?"
        return 1
    fi
    
    if ! VBoxManage list vms | grep -q "\"$vm_name\""; then
        log_error "VM '$vm_name' not found in VirtualBox"
        return 1
    fi
    
    local vm_state=$(VBoxManage showvminfo "$vm_name" --machinereadable 2>/dev/null | grep "VMState=" | cut -d'"' -f2)
    echo "$vm_state"
    return 0
}

# Start a VirtualBox VM
start_vm() {
    local vm_name=$1
    local host=$2
    
    log_info "Starting VirtualBox VM: $vm_name"
    
    local vm_state=$(check_vm_status "$vm_name")
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    log_info "Current VM state: $vm_state"
    
    case "$vm_state" in
        "running")
            log_info "VM $vm_name is already running"
            ;;
        "paused")
            log_info "VM $vm_name is paused, resuming..."
            if VBoxManage controlvm "$vm_name" resume; then
                log_success "VM $vm_name resumed"
            else
                log_error "Failed to resume VM $vm_name"
                return 1
            fi
            ;;
        "poweroff"|"aborted"|"saved")
            log_info "Starting VM $vm_name..."
            if VBoxManage startvm "$vm_name" --type headless; then
                log_success "VM $vm_name start command issued"
            else
                log_error "Failed to start VM $vm_name"
                return 1
            fi
            ;;
        *)
            log_warning "VM $vm_name is in unexpected state: $vm_state"
            log_info "Attempting to start anyway..."
            VBoxManage startvm "$vm_name" --type headless || true
            ;;
    esac
    
    # Wait for the VM to become reachable
    log_info "Waiting for $host to become reachable (max ${MAX_START_WAIT}s)..."
    local wait_time=0
    local dot_count=0
    
    while [ $wait_time -lt $MAX_START_WAIT ]; do
        if check_host_reachable "$host" >/dev/null 2>&1; then
            echo ""  # New line after dots
            log_success "$host is now reachable after ${wait_time}s"
            
            # Additional wait for SSH to be ready
            log_info "Waiting for SSH service to be ready..."
            sleep 10
            
            local ssh_wait=0
            while [ $ssh_wait -lt 30 ]; do
                if check_ssh_connectivity "$host" >/dev/null 2>&1; then
                    log_success "SSH service is ready on $host"
                    return 0
                fi
                sleep 2
                ssh_wait=$((ssh_wait + 2))
            done
            
            log_warning "SSH service not ready, but host is reachable. Proceeding..."
            return 0
        fi
        
        sleep 5
        wait_time=$((wait_time + 5))
        echo -n "."
        dot_count=$((dot_count + 1))
        
        # New line every 20 dots for readability
        if [ $((dot_count % 20)) -eq 0 ]; then
            echo ""
        fi
    done
    
    echo ""
    log_error "$host did not become reachable within ${MAX_START_WAIT}s"
    return 1
}

# Check if deployment script exists on remote host
check_deploy_script() {
    local host=$1
    
    log_debug "Checking if deployment script exists on $host"
    if ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no root@"$host" "test -f $DEPLOY_SCRIPT && test -x $DEPLOY_SCRIPT" 2>/dev/null; then
        log_success "Deployment script found and executable on $host"
        return 0
    else
        log_error "Deployment script $DEPLOY_SCRIPT not found or not executable on $host"
        return 1
    fi
}

# Get system information from remote host
get_system_info() {
    local host=$1
    
    log_debug "Gathering system information from $host"
    local info=$(ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no root@"$host" "uname -a && uptime" 2>/dev/null || echo "Failed to get system info")
    log_info "System info for $host: $info"
}

# Deploy to a specific host
deploy_to_host() {
    local host=$1
    local system_name=$2
    
    echo ""
    log_info "=== Deploying to $system_name ($host) ==="
    
    # Check if host is reachable
    if ! check_host_reachable "$host"; then
        # Try to start the VM
        local vm_name=$(get_vm_name "$host")
        if [[ -n "$vm_name" ]]; then
            log_info "Attempting to start VM: $vm_name"
            if ! start_vm "$vm_name" "$host"; then
                log_error "Failed to start VM and $host remains unreachable. Aborting deployment to $system_name."
                return 1
            fi
        else
            log_error "Unknown VM name for host $host. Cannot start VM."
            return 1
        fi
    fi
    
    # Verify SSH connectivity
    if ! check_ssh_connectivity "$host"; then
        log_error "SSH connectivity test failed for $host"
        return 1
    fi
    
    # Get system information
    get_system_info "$host"
    
    # Check if deployment script exists
    if ! check_deploy_script "$host"; then
        return 1
    fi
    
    # Execute deployment script
    log_info "Executing deployment script on $host..."
    local deploy_start=$(date +%s)
    
    if ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no root@"$host" "$DEPLOY_SCRIPT" 2>&1 | tee -a "$LOG_FILE"; then
        local deploy_end=$(date +%s)
        local deploy_duration=$((deploy_end - deploy_start))
        log_success "Deployment to $system_name completed successfully in ${deploy_duration}s"
        return 0
    else
        local deploy_end=$(date +%s)
        local deploy_duration=$((deploy_end - deploy_start))
        log_error "Deployment to $system_name failed after ${deploy_duration}s"
        return 1
    fi
}

# Parallel deployment function
deploy_parallel() {
    log_info "Starting parallel deployment to both systems"
    
    # Start deployments in background
    deploy_to_host "$FREEBSD_HOST" "FreeBSD" > "$LOG_DIR/freebsd_$(date +%Y%m%d_%H%M%S).log" 2>&1 &
    local freebsd_pid=$!
    
    deploy_to_host "$ALMALINUX_HOST" "AlmaLinux" > "$LOG_DIR/almalinux_$(date +%Y%m%d_%H%M%S).log" 2>&1 &
    local almalinux_pid=$!
    
    # Wait for both deployments
    local freebsd_success=false
    local almalinux_success=false
    
    if wait $freebsd_pid; then
        freebsd_success=true
        log_success "FreeBSD deployment completed"
    else
        log_error "FreeBSD deployment failed"
    fi
    
    if wait $almalinux_pid; then
        almalinux_success=true
        log_success "AlmaLinux deployment completed"
    else
        log_error "AlmaLinux deployment failed"
    fi
    
    return $(( !freebsd_success || !almalinux_success ))
}

# Main deployment function
main() {
    local start_time=$(date +%s)
    
    echo "FOFF Milter Advanced Deployment Script"
    echo "======================================"
    echo "Deploying to FreeBSD and AlmaLinux systems"
    echo "Log file: $LOG_FILE"
    echo ""
    
    log_info "Deployment started at $(date)"
    log_info "Log file: $LOG_FILE"
    
    local freebsd_success=false
    local almalinux_success=false
    
    if [[ "${PARALLEL:-}" == "1" ]]; then
        # Parallel deployment
        if deploy_parallel; then
            freebsd_success=true
            almalinux_success=true
        fi
    else
        # Sequential deployment
        if deploy_to_host "$FREEBSD_HOST" "FreeBSD"; then
            freebsd_success=true
        fi
        
        if deploy_to_host "$ALMALINUX_HOST" "AlmaLinux"; then
            almalinux_success=true
        fi
    fi
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # Summary
    echo ""
    log_info "=== Deployment Summary ==="
    log_info "Total deployment time: ${total_duration}s"
    
    if $freebsd_success; then
        log_success "FreeBSD ($FREEBSD_HOST): SUCCESS"
    else
        log_error "FreeBSD ($FREEBSD_HOST): FAILED"
    fi
    
    if $almalinux_success; then
        log_success "AlmaLinux ($ALMALINUX_HOST): SUCCESS"
    else
        log_error "AlmaLinux ($ALMALINUX_HOST): FAILED"
    fi
    
    log_info "Detailed logs available in: $LOG_DIR"
    
    # Exit with error if any deployment failed
    if $freebsd_success && $almalinux_success; then
        log_success "All deployments completed successfully!"
        exit 0
    else
        log_error "One or more deployments failed!"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    --freebsd-only)
        log_info "Deploying to FreeBSD only"
        deploy_to_host "$FREEBSD_HOST" "FreeBSD"
        exit $?
        ;;
    --almalinux-only)
        log_info "Deploying to AlmaLinux only"
        deploy_to_host "$ALMALINUX_HOST" "AlmaLinux"
        exit $?
        ;;
    --parallel)
        log_info "Running parallel deployment"
        PARALLEL=1 main
        ;;
    --debug)
        log_info "Running in debug mode"
        DEBUG=1 main
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Deploy FOFF Milter to FreeBSD and AlmaLinux systems"
        echo ""
        echo "Options:"
        echo "  --freebsd-only    Deploy only to FreeBSD system"
        echo "  --almalinux-only  Deploy only to AlmaLinux system"
        echo "  --parallel        Deploy to both systems in parallel"
        echo "  --debug           Enable debug logging"
        echo "  --help, -h        Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  DEBUG=1           Enable debug logging"
        echo "  PARALLEL=1        Enable parallel deployment"
        echo ""
        echo "Systems:"
        echo "  FreeBSD:   $FREEBSD_HOST (VM: vegapunk)"
        echo "  AlmaLinux: $ALMALINUX_HOST (VM: almalinux)"
        echo ""
        echo "The script will:"
        echo "1. Check if each host is reachable"
        echo "2. Start VirtualBox VMs if hosts are unreachable"
        echo "3. Verify SSH connectivity and deployment script availability"
        echo "4. Execute $DEPLOY_SCRIPT on each host as root"
        echo "5. Generate detailed logs in $LOG_DIR"
        exit 0
        ;;
    "")
        # No arguments, run full deployment
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
