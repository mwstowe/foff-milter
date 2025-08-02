#!/bin/bash

# FOFF Milter Deployment Script
# Deploys to FreeBSD (vegapunk.johnson.home) and AlmaLinux (almalinux.johnson.home)

set -e  # Exit on any error

# Configuration
FREEBSD_HOST="vegapunk.johnson.home"
ALMALINUX_HOST="almalinux.johnson.home"
DEPLOY_SCRIPT="/usr/tools/deploy_foff.sh"
TIMEOUT=30
MAX_START_WAIT=120

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if a host is reachable
check_host_reachable() {
    local host=$1
    log_info "Checking if $host is reachable..."
    
    if ping -c 1 -W $TIMEOUT "$host" >/dev/null 2>&1; then
        log_success "$host is reachable"
        return 0
    else
        log_warning "$host is not reachable"
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

# Start a VirtualBox VM
start_vm() {
    local vm_name=$1
    local host=$2
    
    log_info "Starting VirtualBox VM: $vm_name"
    
    # Check if VirtualBox is available
    if ! command -v VBoxManage >/dev/null 2>&1; then
        log_error "VBoxManage command not found. Is VirtualBox installed?"
        return 1
    fi
    
    # Check if VM exists
    if ! VBoxManage list vms | grep -q "\"$vm_name\""; then
        log_error "VM '$vm_name' not found in VirtualBox"
        return 1
    fi
    
    # Check current VM state
    local vm_state=$(VBoxManage showvminfo "$vm_name" --machinereadable | grep "VMState=" | cut -d'"' -f2)
    log_info "Current VM state: $vm_state"
    
    if [[ "$vm_state" == "running" ]]; then
        log_info "VM $vm_name is already running"
    else
        log_info "Starting VM $vm_name..."
        if VBoxManage startvm "$vm_name" --type headless; then
            log_success "VM $vm_name start command issued"
        else
            log_error "Failed to start VM $vm_name"
            return 1
        fi
    fi
    
    # Wait for the VM to become reachable
    log_info "Waiting for $host to become reachable (max ${MAX_START_WAIT}s)..."
    local wait_time=0
    while [ $wait_time -lt $MAX_START_WAIT ]; do
        if check_host_reachable "$host"; then
            log_success "$host is now reachable after ${wait_time}s"
            return 0
        fi
        sleep 5
        wait_time=$((wait_time + 5))
        echo -n "."
    done
    
    echo ""
    log_error "$host did not become reachable within ${MAX_START_WAIT}s"
    return 1
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
    
    # Execute deployment script
    log_info "Executing deployment script on $host..."
    if ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no root@"$host" "$DEPLOY_SCRIPT"; then
        log_success "Deployment to $system_name completed successfully"
        return 0
    else
        log_error "Deployment to $system_name failed"
        return 1
    fi
}

# Main deployment function
main() {
    echo "FOFF Milter Deployment Script"
    echo "============================="
    echo "Deploying to FreeBSD and AlmaLinux systems"
    echo ""
    
    local freebsd_success=false
    local almalinux_success=false
    
    # Deploy to FreeBSD
    if deploy_to_host "$FREEBSD_HOST" "FreeBSD"; then
        freebsd_success=true
    fi
    
    # Deploy to AlmaLinux
    if deploy_to_host "$ALMALINUX_HOST" "AlmaLinux"; then
        almalinux_success=true
    fi
    
    # Summary
    echo ""
    log_info "=== Deployment Summary ==="
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
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Deploy FOFF Milter to FreeBSD and AlmaLinux systems"
        echo ""
        echo "Options:"
        echo "  --freebsd-only    Deploy only to FreeBSD system"
        echo "  --almalinux-only  Deploy only to AlmaLinux system"
        echo "  --help, -h        Show this help message"
        echo ""
        echo "Systems:"
        echo "  FreeBSD:   $FREEBSD_HOST (VM: vegapunk)"
        echo "  AlmaLinux: $ALMALINUX_HOST (VM: almalinux)"
        echo ""
        echo "The script will:"
        echo "1. Check if each host is reachable"
        echo "2. Start VirtualBox VMs if hosts are unreachable"
        echo "3. Execute $DEPLOY_SCRIPT on each host as root"
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
