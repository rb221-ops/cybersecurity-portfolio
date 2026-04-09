#!/bin/bash
# Secure Infrastructure Hardening Script
# Comprehensive system hardening for Linux servers
# Author: Riley (rb221-ops)

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[!]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    apt-get update
    apt-get upgrade -y
    apt-get autoremove -y
    log_success "System packages updated"
}

# Harden SSH configuration
harden_ssh() {
    log "Hardening SSH configuration..."
    
    SSH_CONFIG="/etc/ssh/sshd_config"
    
    # Backup original config
    cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"
    
    # SSH security settings
    cat >> "$SSH_CONFIG" <<EOF

# Security Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
Compression delayed
TCPKeepAlive yes
PermitEmptyPasswords no
PermitUserEnvironment no
IgnoreRhosts yes
RhostsRSAAuthentication no
RSAAuthentication yes
AllowUsers *@*.example.com
LoginGraceTime 20
StrictModes yes
EOF
    
    # Validate SSH config
    if sshd -t; then
        systemctl restart sshd
        log_success "SSH hardened successfully"
    else
        log_error "SSH config validation failed, restoring backup"
        cp "${SSH_CONFIG}.bak" "$SSH_CONFIG"
    fi
}

# Configure firewall
configure_firewall() {
    log "Configuring UFW firewall..."
    
    # Enable UFW
    ufw --force enable
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (adjust port as needed)
    ufw allow 22/tcp
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    log_success "Firewall configured"
    ufw status
}

# Disable unnecessary services
disable_services() {
    log "Disabling unnecessary services..."
    
    services_to_disable=(
        "avahi-daemon"
        "cups"
        "isc-dhcp-server"
        "slapd"
        "nfs-server"
        "bind9"
        "vsftpd"
        "apache2"
        "dovecot"
        "snmpd"
        "rsync"
        "tftp"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null; then
            systemctl --now disable "$service"
            log "Disabled $service"
        fi
    done
    
    log_success "Unnecessary services disabled"
}

# Configure system logging
configure_logging() {
    log "Configuring system logging..."
    
    # Install auditd if not present
    if ! command -v auditd &> /dev/null; then
        apt-get install -y auditd audispd-plugins
    fi
    
    # Add audit rules
    cat >> /etc/audit/rules.d/hardening.rules <<EOF
# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor unauthorized access attempts
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -F auid>=1000 -F auid!=-1 -k delete

# Monitor system administration
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
EOF
    
    # Restart auditd
    service auditd restart
    
    log_success "Audit logging configured"
}

# Configure file permissions
harden_file_permissions() {
    log "Hardening file permissions..."
    
    # Sensitive files
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 000 /etc/shadow
    chmod 000 /etc/gshadow
    chmod 644 /etc/hosts
    chmod 644 /etc/hosts.allow
    chmod 644 /etc/hosts.deny
    
    # Restrict access to log files
    find /var/log -type f -exec chmod g-wx,o-rwx {} \;
    
    # Restrict SUID/SGID files
    log_warning "Consider restricting SUID/SGID files based on your requirements"
    
    log_success "File permissions hardened"
}

# Configure SELinux/AppArmor
configure_access_control() {
    log "Configuring access control..."
    
    # Check if AppArmor is available
    if systemctl is-enabled apparmor 2>/dev/null; then
        log "AppArmor is enabled"
        aa-enforce /etc/apparmor.d/*
    fi
    
    # Enable audit mode for AppArmor
    log_success "Access control configured"
}

# Disable unnecessary network protocols
disable_network_protocols() {
    log "Disabling unnecessary network protocols..."
    
    protocols=(
        "dccp"
        "sctp"
        "rds"
        "tipc"
    )
    
    for protocol in "${protocols[@]}"; do
        echo "install $protocol /bin/true" >> /etc/modprobe.d/hardening.conf
        log "Disabled $protocol"
    done
    
    log_success "Network protocols hardened"
}

# Configure kernel parameters
harden_kernel() {
    log "Hardening kernel parameters..."
    
    # Create/update sysctl hardening config
    cat > /etc/sysctl.d/99-hardening.conf <<EOF
# Kernel hardening parameters

# Restrict kernel module loading
kernel.modules_disabled = 1

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict ptrace access
kernel.yama.ptrace_scope = 2

# Restrict access to kernel logs
kernel.printk = 3 3 3 3

# Hide exposed kernel pointers
kernel.kptr_restrict = 2

# Hide exposed kernel address space
kernel.perf_event_paranoid = 2

# Restrict sysrq functionality
kernel.sysrq = 0

# Disable magic SysRq key
kernel.sysrq = 0

# Increase PID max value
kernel.pid_max = 65535

# Restrict access to kernel debugfs
kernel.debugfs_restrict_access = 1

# Network hardening

# Disable IPv4 forwarding
net.ipv4.ip_forward = 0

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding = 0

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable logging of suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable TCP timestamps
net.ipv4.tcp_timestamps = 1

# Increase TCP backlog
net.ipv4.tcp_max_syn_backlog = 2048

# Set TCP max listen backlog
net.core.somaxconn = 2048
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-hardening.conf
    
    log_success "Kernel parameters hardened"
}

# Configure password policies
configure_password_policy() {
    log "Configuring password policy..."
    
    # Install libpam-pwquality if not present
    if ! command -v pwmake &> /dev/null; then
        apt-get install -y libpam-pwquality
    fi
    
    # Configure PAM password quality
    cat > /etc/security/pwquality.conf <<EOF
# Password quality requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
difok = 3
maxrepeat = 3
usercheck = 1
enforce_for_root
EOF
    
    # Configure password expiration
    cat >> /etc/login.defs <<EOF

# Password aging settings
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
PASS_MIN_LEN    14
EOF
    
    log_success "Password policy configured"
}

# Install and configure aide (file integrity)
configure_aide() {
    log "Configuring AIDE (File Integrity Monitoring)..."
    
    if ! command -v aide &> /dev/null; then
        apt-get install -y aide aide-common
    fi
    
    # Initialize AIDE database
    aideinit
    
    # Create cron job for daily checks
    cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/bin/aide --check
EOF
    chmod 755 /etc/cron.daily/aide-check
    
    log_success "AIDE configured for file integrity monitoring"
}

# Configure fail2ban
configure_fail2ban() {
    log "Installing and configuring Fail2ban..."
    
    apt-get install -y fail2ban
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@example.com
sendername = Fail2Ban
mta = sendmail

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    systemctl restart fail2ban
    
    log_success "Fail2ban configured"
}

# Generate hardening report
generate_report() {
    log "Generating hardening report..."
    
    REPORT_FILE="/var/log/hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "========================================"
        echo "SECURITY HARDENING REPORT"
        echo "========================================"
        echo "Generated: $(date)"
        echo ""
        echo "System Information:"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "OS: $(cat /etc/os-release | grep PRETTY_NAME)"
        echo ""
        echo "Security Status:"
        echo "SELinux/AppArmor: $(systemctl is-enabled apparmor || echo 'Not enabled')"
        echo "UFW Firewall: $(ufw status | head -1)"
        echo "SSH Status: $(systemctl is-active ssh)"
        echo "Fail2ban: $(systemctl is-active fail2ban)"
        echo ""
        echo "Open Ports:"
        ss -tlnp | grep LISTEN
        echo ""
        echo "Running Services:"
        systemctl list-units --type service --state running | head -20
        echo ""
        echo "Security Events:"
        grep -i "denied\|rejected\|error" /var/log/auth.log | tail -20 || echo "No recent security events"
        echo ""
        echo "========================================"
    } | tee "$REPORT_FILE"
    
    log_success "Hardening report saved to $REPORT_FILE"
}

# Main execution
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║  SECURE INFRASTRUCTURE HARDENING AUTOMATION       ║"
    echo "║  Defense-in-Depth Security Configuration          ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    
    log "Starting infrastructure hardening..."
    log "Logging to: $LOG_FILE"
    
    update_system
    harden_ssh
    configure_firewall
    disable_services
    configure_logging
    harden_file_permissions
    configure_access_control
    disable_network_protocols
    harden_kernel
    configure_password_policy
    configure_aide
    configure_fail2ban
    generate_report
    
    log_success "Infrastructure hardening completed successfully!"
    log "Review the hardening report and customize as needed for your environment"
}

# Run main function
main "$@"
