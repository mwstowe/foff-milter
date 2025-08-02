#!/bin/bash

# Test script for FOFF Milter deployment scripts
# This script validates the deployment environment without actually deploying

set -e

# Configuration
FREEBSD_HOST="vegapunk.johnson.home"
ALMALINUX_HOST="almalinux.johnson.home"
DEPLOY_SCRIPT="/usr/tools/deploy_foff.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test functions
test_vboxmanage() {
    log_info "Testing VBoxManage availability..."
    if command -v VBoxManage >/dev/null 2>&1; then
        log_success "VBoxManage is available"
        VBoxManage --version
        return 0
    else
        log_error "VBoxManage not found - VirtualBox may not be installed"
        return 1
    fi
}

test_vm_exists() {
    local vm_name=$1
    log_info "Testing if VM '$vm_name' exists..."
    
    if VBoxManage list vms | grep -q "\"$vm_name\""; then
        log_success "VM '$vm_name' found"
        local vm_state=$(VBoxManage showvminfo "$vm_name" --machinereadable | grep "VMState=" | cut -d'"' -f2)
        log_info "VM state: $vm_state"
        return 0
    else
        log_error "VM '$vm_name' not found"
        return 1
    fi
}

test_host_reachable() {
    local host=$1
    log_info "Testing connectivity to $host..."
    
    if ping -c 1 -W 5 "$host" >/dev/null 2>&1; then
        log_success "$host is reachable"
        return 0
    else
        log_warning "$host is not reachable (VM may be stopped)"
        return 1
    fi
}

test_ssh_connectivity() {
    local host=$1
    log_info "Testing SSH connectivity to $host..."
    
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o BatchMode=yes root@"$host" "echo 'SSH test successful'" >/dev/null 2>&1; then
        log_success "SSH connectivity to $host works"
        return 0
    else
        log_warning "SSH connectivity to $host failed (host may be down or SSH not configured)"
        return 1
    fi
}

test_deploy_script_exists() {
    local host=$1
    log_info "Testing if deployment script exists on $host..."
    
    if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@"$host" "test -f $DEPLOY_SCRIPT && test -x $DEPLOY_SCRIPT" 2>/dev/null; then
        log_success "Deployment script found and executable on $host"
        return 0
    else
        log_error "Deployment script $DEPLOY_SCRIPT not found or not executable on $host"
        return 1
    fi
}

test_deployment_scripts() {
    log_info "Testing deployment scripts..."
    
    if [[ -f "./deploy.sh" && -x "./deploy.sh" ]]; then
        log_success "Basic deployment script (deploy.sh) found and executable"
    else
        log_error "Basic deployment script (deploy.sh) not found or not executable"
    fi
    
    if [[ -f "./deploy_advanced.sh" && -x "./deploy_advanced.sh" ]]; then
        log_success "Advanced deployment script (deploy_advanced.sh) found and executable"
    else
        log_error "Advanced deployment script (deploy_advanced.sh) not found or not executable"
    fi
}

# Main test function
main() {
    echo "FOFF Milter Deployment Test Script"
    echo "=================================="
    echo ""
    
    local tests_passed=0
    local tests_failed=0
    
    # Test VirtualBox
    if test_vboxmanage; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo ""
    
    # Test VMs
    if test_vm_exists "vegapunk"; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo ""
    
    if test_vm_exists "almalinux"; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    echo ""
    
    # Test deployment scripts
    test_deployment_scripts
    echo ""
    
    # Test host connectivity
    if test_host_reachable "$FREEBSD_HOST"; then
        ((tests_passed++))
        
        # Test SSH if host is reachable
        if test_ssh_connectivity "$FREEBSD_HOST"; then
            ((tests_passed++))
            
            # Test deployment script if SSH works
            if test_deploy_script_exists "$FREEBSD_HOST"; then
                ((tests_passed++))
            else
                ((tests_failed++))
            fi
        else
            ((tests_failed++))
        fi
    else
        log_warning "Skipping SSH and deployment script tests for $FREEBSD_HOST (host unreachable)"
        ((tests_failed++))
    fi
    echo ""
    
    if test_host_reachable "$ALMALINUX_HOST"; then
        ((tests_passed++))
        
        # Test SSH if host is reachable
        if test_ssh_connectivity "$ALMALINUX_HOST"; then
            ((tests_passed++))
            
            # Test deployment script if SSH works
            if test_deploy_script_exists "$ALMALINUX_HOST"; then
                ((tests_passed++))
            else
                ((tests_failed++))
            fi
        else
            ((tests_failed++))
        fi
    else
        log_warning "Skipping SSH and deployment script tests for $ALMALINUX_HOST (host unreachable)"
        ((tests_failed++))
    fi
    echo ""
    
    # Summary
    echo "Test Summary"
    echo "============"
    log_success "Tests passed: $tests_passed"
    if [[ $tests_failed -gt 0 ]]; then
        log_error "Tests failed: $tests_failed"
    else
        log_success "Tests failed: $tests_failed"
    fi
    echo ""
    
    if [[ $tests_failed -eq 0 ]]; then
        log_success "All tests passed! Deployment environment is ready."
        echo ""
        echo "You can now run:"
        echo "  ./deploy.sh                    # Basic deployment"
        echo "  ./deploy_advanced.sh           # Advanced deployment"
        echo "  ./deploy_advanced.sh --parallel # Parallel deployment"
        exit 0
    else
        log_error "Some tests failed. Please fix the issues before deploying."
        echo ""
        echo "Common fixes:"
        echo "  - Install VirtualBox if VBoxManage is missing"
        echo "  - Start VMs if hosts are unreachable"
        echo "  - Configure SSH keys for passwordless access"
        echo "  - Ensure /usr/tools/deploy_foff.sh exists on target systems"
        exit 1
    fi
}

# Handle arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Test the FOFF Milter deployment environment"
        echo ""
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo ""
        echo "This script tests:"
        echo "  - VirtualBox installation and VM availability"
        echo "  - Host connectivity"
        echo "  - SSH access to target systems"
        echo "  - Deployment script availability"
        echo "  - Deployment script executability"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
