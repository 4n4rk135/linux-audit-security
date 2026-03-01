#!/bin/bash

# Simple Linux Security Audit Script
# This script performs basic security checks on a Linux system.
# Run with: sudo bash linux_audit_security.sh
# Requires root privileges for full functionality.
# Created by aguskb

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        *)
            echo "[INFO] $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "WARN" "This script should be run as root for full functionality"
    else
        print_status "PASS" "Running with root privileges"
    fi
}

# Check user accounts
check_users() {
    echo "=== User Account Security ==="

    # Check for users with UID 0 (root privileges)
    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    if [[ $(echo "$root_users" | wc -l) -gt 1 ]]; then
        print_status "WARN" "Multiple users with UID 0: $root_users"
    else
        print_status "PASS" "Only root has UID 0"
    fi

    # Check for users with empty passwords
    empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pass" ]]; then
        print_status "FAIL" "Users with empty passwords: $empty_pass"
    else
        print_status "PASS" "No users with empty passwords"
    fi

    # Check for users without passwords (locked accounts are OK)
    no_pass=$(awk -F: '($2 == "!" || $2 == "*") {print $1}' /etc/shadow 2>/dev/null | grep -v root)
    if [[ -n "$no_pass" ]]; then
        print_status "INFO" "Users without passwords (locked): $no_pass"
    fi
}

# Check file permissions
check_permissions() {
    echo "=== File Permissions ==="

    # Check /etc/passwd permissions
    if [[ $(stat -c %a /etc/passwd) -le 644 ]]; then
        print_status "PASS" "/etc/passwd has correct permissions"
    else
        print_status "FAIL" "/etc/passwd has incorrect permissions"
    fi

    # Check /etc/shadow permissions
    if [[ $(stat -c %a /etc/shadow) -le 600 ]]; then
        print_status "PASS" "/etc/shadow has correct permissions"
    else
        print_status "FAIL" "/etc/shadow has incorrect permissions"
    fi

    # Check /etc/group permissions
    if [[ $(stat -c %a /etc/group) -le 644 ]]; then
        print_status "PASS" "/etc/group has correct permissions"
    else
        print_status "FAIL" "/etc/group has incorrect permissions"
    fi
}

# Check running services
check_services() {
    echo "=== Running Services ==="

    # Check for common insecure services
    insecure_services=("telnet" "rsh" "rlogin" "rexec" "ftp" "tftp")

    for service in "${insecure_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_status "FAIL" "Insecure service running: $service"
        fi
    done

    # Check SSH service
    if systemctl is-active --quiet sshd 2>/dev/null; then
        print_status "INFO" "SSH service is running"
        # Check SSH config for root login
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            print_status "FAIL" "SSH allows root login"
        else
            print_status "PASS" "SSH root login disabled"
        fi
    else
        print_status "INFO" "SSH service not running"
    fi
}

# Check open ports
check_ports() {
    echo "=== Open Ports ==="

    if command -v netstat &> /dev/null; then
        open_ports=$(netstat -tuln | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u)
    elif command -v ss &> /dev/null; then
        open_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | sed 's/.*://' | sort -u)
    else
        print_status "WARN" "Neither netstat nor ss available for port checking"
        return
    fi

    dangerous_ports=(21 23 25 53 69 135 137 138 139 445 993 995)

    for port in $open_ports; do
        if [[ " ${dangerous_ports[@]} " =~ " ${port} " ]]; then
            print_status "WARN" "Potentially dangerous port open: $port"
        fi
    done

    print_status "INFO" "Open ports: $open_ports"
}

# Check firewall status
check_firewall() {
    echo "=== Firewall Status ==="

    if command -v ufw &> /dev/null; then
        ufw_status=$(ufw status | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            print_status "PASS" "UFW firewall is active"
        else
            print_status "FAIL" "UFW firewall is inactive"
        fi
    elif command -v firewall-cmd &> /dev/null; then
        fw_status=$(firewall-cmd --state 2>/dev/null)
        if [[ "$fw_status" == "running" ]]; then
            print_status "PASS" "Firewalld is running"
        else
            print_status "FAIL" "Firewalld is not running"
        fi
    else
        print_status "WARN" "No recognized firewall (ufw/firewalld) found"
    fi
}

# Check system updates
check_updates() {
    echo "=== System Updates ==="

    if command -v apt &> /dev/null; then
        updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable")
        if [[ $updates -gt 0 ]]; then
            print_status "WARN" "$updates packages can be upgraded"
        else
            print_status "PASS" "System is up to date"
        fi
    elif command -v yum &> /dev/null; then
        updates=$(yum check-update 2>/dev/null | grep -c "updates")
        if [[ $updates -gt 0 ]]; then
            print_status "WARN" "System updates available"
        else
            print_status "PASS" "System is up to date"
        fi
    else
        print_status "INFO" "Package manager not recognized (apt/yum)"
    fi
}

# Check sudo configuration
check_sudo() {
    echo "=== Sudo Configuration ==="

    if [[ -f /etc/sudoers ]]; then
        if grep -q "NOPASSWD" /etc/sudoers; then
            print_status "WARN" "NOPASSWD found in sudoers - review for security"
        else
            print_status "PASS" "No NOPASSWD entries in sudoers"
        fi
    else
        print_status "INFO" "Sudoers file not found"
    fi
}

# Check for malicious/dangerous scripts
check_malicious_scripts() {
    echo "=== Malicious Scripts Detection ==="

    # Common web shells and backdoors
    dangerous_patterns=(
        "c99"           # C99 web shell
        "r57"           # R57 web shell
        "wshell"        # WS Hell
        "shellbot"      # Shell Bot
        "phpshell"     # PHP Shell
        "c100"          # C100 web shell
        "rootkit"       # Rootkit
        "b374k"         # B374k shell
        "mini shell"    # Mini shell
        "admin shell"   # Admin shell
        "simple shell"  # Simple shell
        "bitch"         # Bitch shell
        "hacker"        # Hacker shell
        "cmd"           # CMD shell
        "backdoor"      # Backdoor
        "webshell"      # Webshell
        "symlink"       # Symlink bypass
        "killer"        # Killer script
        "安全的"         # Chinese "safe" - often used in shells
        "shell_exec"    # PHP shell function
        "passthru"      # PHP shell function
        "system"        # PHP shell function
        "exec"          # PHP shell function
    )

    # Common locations to scan
    scan_dirs=("/var/www" "/home" "/tmp" "/var/tmp" "/root" "/opt")

    dangerous_found=0

    for dir in "${scan_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            for pattern in "${dangerous_patterns[@]}"; do
                # Search for files containing dangerous patterns
                results=$(grep -rl "$pattern" "$dir" 2>/dev/null | head -20)
                if [[ -n "$results" ]]; then
                    while IFS= read -r file; do
                        if [[ -f "$file" ]]; then
                            print_status "FAIL" "Dangerous script found: $file (pattern: $pattern)"
                            dangerous_found=1
                        fi
                    done <<< "$results"
                fi
            done
        fi
    done

    if [[ $dangerous_found -eq 0 ]]; then
        print_status "PASS" "No known malicious scripts detected"
    fi

    # Check for recently created executable files in tmp
    recent_executables=$(find /tmp -type f -executable -mtime -7 2>/dev/null)
    if [[ -n "$recent_executables" ]]; then
        print_status "WARN" "Recent executable files found in /tmp:"
        echo "$recent_executables" | head -10 | while read -r f; do
            echo "  -> $f"
        done
    fi

    # Check for hidden suspicious files
    hidden_suspicious=$(find / -name ".*" -type f \( -name "*sh*" -o -name "*hack*" -o -name "*back*" \) 2>/dev/null | grep -v "/proc" | grep -v "/sys" | head -20)
    if [[ -n "$hidden_suspicious" ]]; then
        print_status "WARN" "Hidden suspicious files found:"
        echo "$hidden_suspicious" | while read -r f; do
            echo "  -> $f"
        done
    fi

    # Check for cron jobs owned by other users
    suspicious_crons=$(find /var/spool/cron -type f 2>/dev/null | grep -v "crontabs")
    if [[ -n "$suspicious_crons" ]]; then
        print_status "WARN" "Non-standard cron files found:"
        echo "$suspicious_crons" | while read -r f; do
            echo "  -> $f"
        done
    fi

    # Check for suspicious SSH keys
    if [[ -d "/root/.ssh" ]]; then
        authorized_keys="/root/.ssh/authorized_keys"
        if [[ -f "$authorized_keys" ]]; then
            key_count=$(wc -l < "$authorized_keys")
            if [[ $key_count -gt 5 ]]; then
                print_status "WARN" "Multiple SSH authorized keys for root: $key_count keys"
            fi
        fi
    fi
}

# Check kernel security settings
check_kernel_security() {
    echo "=== Kernel Security Settings ==="

    # Check important sysctl parameters
    sysctl_checks=(
        "kernel.kptr_restrict=1"           # Hide kernel pointers
        "kernel.dmesg_restrict=1"          # Restrict dmesg access
        "kernel.printk=3 3 3 3"            # Restrict kernel log access
        "kernel.unprivileged_bpf_disabled=1" # Disable unprivileged BPF
        "net.core.bpf_jit_harden=2"        # Harden BPF JIT
        "kernel.yama.ptrace_scope=1"       # Restrict ptrace
        "vm.mmap_min_addr=65536"           # Prevent NULL deref attacks
        "kernel.kexec_load_disabled=1"     # Disable kexec
        "dev.tty.ldisc_autoload=0"         # Disable TTY line discipline autoload
        "fs.suid_dumpable=0"               # Disable core dumps with SUID
        "kernel.sysrq=0"                   # Disable SysRq
        "kernel.core_uses_pid=1"           # Include PID in core dumps
        "net.ipv4.tcp_syncookies=1"        # Enable SYN cookies
        "net.ipv4.tcp_rfc1337=1"           # Enable RFC1337
        "net.ipv4.conf.all.rp_filter=1"    # Enable reverse path filtering
        "net.ipv4.conf.default.rp_filter=1"
        "net.ipv4.conf.all.accept_redirects=0" # Disable ICMP redirects
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.accept_source_route=0" # Disable source routing
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv4.conf.all.send_redirects=0" # Disable send redirects
        "net.ipv4.conf.default.send_redirects=0"
        "net.ipv4.conf.all.log_martians=1" # Log suspicious packets
        "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1" # Ignore ICMP broadcasts
        "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.tcp_timestamps=0"        # Disable TCP timestamps
        "net.ipv6.conf.all.accept_ra=0"    # Disable IPv6 router advertisements
        "net.ipv6.conf.default.accept_ra=0"
        "net.ipv6.conf.all.accept_redirects=0" # Disable IPv6 redirects
        "net.ipv6.conf.default.accept_redirects=0"
    )

    sysctl_pass=0
    sysctl_total=${#sysctl_checks[@]}

    for check in "${sysctl_checks[@]}"; do
        param=$(echo "$check" | cut -d'=' -f1)
        expected=$(echo "$check" | cut -d'=' -f2)
        current=$(sysctl -n "$param" 2>/dev/null)
        if [[ "$current" == "$expected" ]]; then
            ((sysctl_pass++))
        fi
    done

    if [[ $sysctl_pass -eq $sysctl_total ]]; then
        print_status "PASS" "All kernel security settings configured correctly"
    elif [[ $sysctl_pass -ge $((sysctl_total * 3 / 4)) ]]; then
        print_status "WARN" "Most kernel security settings configured ($sysctl_pass/$sysctl_total)"
    else
        print_status "FAIL" "Many kernel security settings missing ($sysctl_pass/$sysctl_total)"
    fi
}

# Check SELinux/AppArmor status
check_mandatory_access_control() {
    echo "=== Mandatory Access Control ==="

    if command -v getenforce &> /dev/null; then
        selinux_status=$(getenforce 2>/dev/null)
        if [[ "$selinux_status" == "Enforcing" ]]; then
            print_status "PASS" "SELinux is in enforcing mode"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            print_status "WARN" "SELinux is in permissive mode"
        else
            print_status "FAIL" "SELinux is disabled"
        fi
    elif command -v apparmor_status &> /dev/null; then
        apparmor_loaded=$(apparmor_status 2>/dev/null | grep -c "profiles are loaded")
        if [[ $apparmor_loaded -gt 0 ]]; then
            print_status "PASS" "AppArmor is active with $apparmor_loaded profiles"
        else
            print_status "WARN" "AppArmor is installed but no profiles loaded"
        fi
    else
        print_status "WARN" "No SELinux or AppArmor detected"
    fi
}

# Check SSH configuration security
check_ssh_security() {
    echo "=== SSH Configuration Security ==="

    ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        ssh_checks=(
            "PermitRootLogin=no"
            "PermitEmptyPasswords=no"
            "PasswordAuthentication=yes"
            "X11Forwarding=no"
            "AllowTcpForwarding=no"
            "MaxAuthTries=3"
            "ClientAliveInterval=300"
            "ClientAliveCountMax=2"
            "LoginGraceTime=30"
            "Protocol=2"
        )

        ssh_pass=0
        ssh_total=${#ssh_checks[@]}

        for check in "${ssh_checks[@]}"; do
            param=$(echo "$check" | cut -d'=' -f1)
            expected=$(echo "$check" | cut -d'=' -f2)
            current=$(grep "^$param" "$ssh_config" 2>/dev/null | awk '{print $2}')
            if [[ "$current" == "$expected" ]]; then
                ((ssh_pass++))
            fi
        done

        if [[ $ssh_pass -eq $ssh_total ]]; then
            print_status "PASS" "SSH configuration is secure"
        elif [[ $ssh_pass -ge $((ssh_total * 2 / 3)) ]]; then
            print_status "WARN" "SSH configuration mostly secure ($ssh_pass/$ssh_total)"
        else
            print_status "FAIL" "SSH configuration needs hardening ($ssh_pass/$ssh_total)"
        fi

        # Check SSH key strength
        if [[ -d "/etc/ssh" ]]; then
            weak_keys=$(find /etc/ssh -name "ssh_host_*_key" -exec ssh-keygen -l -f {} \; 2>/dev/null | awk '$1 < 2048 {print $NF}' | wc -l)
            if [[ $weak_keys -gt 0 ]]; then
                print_status "WARN" "$weak_keys SSH host keys are weaker than 2048 bits"
            else
                print_status "PASS" "All SSH host keys are at least 2048 bits"
            fi
        fi
    else
        print_status "WARN" "SSH configuration file not found"
    fi
}

# Check password policies
check_password_policies() {
    echo "=== Password Policies ==="

    # Check PAM password settings
    pam_pwquality="/etc/security/pwquality.conf"
    if [[ -f "$pam_pwquality" ]]; then
        minlen=$(grep "^minlen" "$pam_pwquality" 2>/dev/null | awk '{print $3}')
        if [[ -n "$minlen" && $minlen -ge 12 ]]; then
            print_status "PASS" "Minimum password length: $minlen"
        else
            print_status "FAIL" "Minimum password length too short: ${minlen:-0}"
        fi
    fi

    # Check login.defs
    login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        pass_max_days=$(grep "^PASS_MAX_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
        pass_min_days=$(grep "^PASS_MIN_DAYS" "$login_defs" 2>/dev/null | awk '{print $2}')
        pass_warn_age=$(grep "^PASS_WARN_AGE" "$login_defs" 2>/dev/null | awk '{print $2}')

        if [[ -n "$pass_max_days" && $pass_max_days -le 90 ]]; then
            print_status "PASS" "Password expires every $pass_max_days days"
        else
            print_status "WARN" "Password expiration too long: ${pass_max_days:-365} days"
        fi

        if [[ -n "$pass_warn_age" && $pass_warn_age -ge 7 ]]; then
            print_status "PASS" "Password warning age: $pass_warn_age days"
        else
            print_status "WARN" "Password warning age too short: ${pass_warn_age:-0} days"
        fi
    fi

    # Check for accounts with no password expiration
    no_expire=$(chage -l root 2>/dev/null | grep "Password expires" | grep -c "never")
    if [[ $no_expire -gt 0 ]]; then
        print_status "WARN" "Some accounts have no password expiration"
    fi
}

# Check audit daemon status
check_audit_daemon() {
    echo "=== Audit Daemon Status ==="

    if systemctl is-active --quiet auditd 2>/dev/null; then
        print_status "PASS" "Audit daemon is running"
        # Check audit rules
        audit_rules_count=$(auditctl -l 2>/dev/null | wc -l)
        if [[ $audit_rules_count -gt 10 ]]; then
            print_status "PASS" "Audit rules configured ($audit_rules_count rules)"
        else
            print_status "WARN" "Few audit rules configured ($audit_rules_count rules)"
        fi
    elif systemctl is-active --quiet rsyslog 2>/dev/null; then
        print_status "INFO" "rsyslog is running (auditd not found)"
    else
        print_status "FAIL" "No audit daemon or logging service running"
    fi
}

# Check file system security
check_filesystem_security() {
    echo "=== File System Security ==="

    # Check /tmp mount options
    tmp_mount=$(mount | grep " /tmp " 2>/dev/null)
    if [[ -n "$tmp_mount" ]]; then
        if echo "$tmp_mount" | grep -q "noexec"; then
            print_status "PASS" "/tmp mounted with noexec"
        else
            print_status "WARN" "/tmp not mounted with noexec"
        fi

        if echo "$tmp_mount" | grep -q "nosuid"; then
            print_status "PASS" "/tmp mounted with nosuid"
        else
            print_status "WARN" "/tmp not mounted with nosuid"
        fi
    fi

    # Check /var mount options
    var_mount=$(mount | grep " /var " 2>/dev/null)
    if [[ -n "$var_mount" ]]; then
        if echo "$var_mount" | grep -q "nodev"; then
            print_status "PASS" "/var mounted with nodev"
        else
            print_status "INFO" "/var not mounted with nodev"
        fi
    fi

    # Check for world-writable files
    world_writable=$(find / -type f -perm -002 2>/dev/null | grep -v "/proc" | grep -v "/sys" | wc -l)
    if [[ $world_writable -gt 0 ]]; then
        print_status "WARN" "$world_writable world-writable files found"
    else
        print_status "PASS" "No world-writable files found"
    fi
}

# Check system resource limits
check_resource_limits() {
    echo "=== System Resource Limits ==="

    limits_conf="/etc/security/limits.conf"
    if [[ -f "$limits_conf" ]]; then
        hard_limits=$(grep -c "hard.*core.*0" "$limits_conf" 2>/dev/null)
        if [[ $hard_limits -gt 0 ]]; then
            print_status "PASS" "Core dumps disabled for some users"
        else
            print_status "WARN" "Core dumps may be enabled"
        fi

        maxlogins=$(grep "maxlogins" "$limits_conf" 2>/dev/null | head -1 | awk '{print $4}')
        if [[ -n "$maxlogins" && $maxlogins -le 10 ]]; then
            print_status "PASS" "Max logins limited to $maxlogins"
        else
            print_status "INFO" "Max logins not restricted"
        fi
    fi
}

# Check USB device restrictions
check_usb_security() {
    echo "=== USB Device Security ==="

    if [[ -d "/sys/bus/usb" ]]; then
        usb_devices=$(lsusb 2>/dev/null | wc -l)
        if [[ $usb_devices -gt 0 ]]; then
            print_status "INFO" "$usb_devices USB devices detected"
        fi

        # Check for USBGuard
        if command -v usbguard &> /dev/null; then
            usbguard_status=$(systemctl is-active usbguard 2>/dev/null)
            if [[ "$usbguard_status" == "active" ]]; then
                print_status "PASS" "USBGuard is active"
            else
                print_status "WARN" "USBGuard installed but not active"
            fi
        else
            print_status "INFO" "USBGuard not installed"
        fi
    fi
}

# Check time synchronization
check_time_sync() {
    echo "=== Time Synchronization ==="

    if systemctl is-active --quiet chronyd 2>/dev/null; then
        print_status "PASS" "Chrony NTP daemon is running"
    elif systemctl is-active --quiet ntpd 2>/dev/null; then
        print_status "PASS" "NTP daemon is running"
    elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        print_status "PASS" "Systemd timesync is running"
    else
        print_status "FAIL" "No time synchronization service running"
    fi
}

# Check PAM configuration
check_pam_config() {
    echo "=== PAM Configuration ==="

    pam_system_auth="/etc/pam.d/system-auth"
    pam_password_auth="/etc/pam.d/password-auth"

    if [[ -f "$pam_system_auth" ]] || [[ -f "$pam_password_auth" ]]; then
        # Check for nullok (allows empty passwords)
        nullok_check=$(grep -r "nullok" /etc/pam.d/ 2>/dev/null | wc -l)
        if [[ $nullok_check -eq 0 ]]; then
            print_status "PASS" "Empty passwords not allowed"
        else
            print_status "FAIL" "Empty passwords may be allowed (nullok found)"
        fi

        # Check for remember (password history)
        remember_check=$(grep -r "remember" /etc/pam.d/ 2>/dev/null | wc -l)
        if [[ $remember_check -gt 0 ]]; then
            print_status "PASS" "Password history enabled"
        else
            print_status "WARN" "Password history not configured"
        fi
    else
        print_status "INFO" "PAM configuration files not found"
    fi
}

# Check network connections and suspicious activity
check_network_connections() {
    echo "=== Network Connections & Suspicious Activity ==="

    # Check established connections
    established_conns=$(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)
    if [[ $established_conns -gt 0 ]]; then
        print_status "INFO" "Active connections: $established_conns"

        # Check for suspicious foreign IPs
        suspicious_ips=$(netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | grep -v "127.0.0.1\|10\.\|172\.16\.\|192\.168\." | head -10)
        if [[ -n "$suspicious_ips" ]]; then
            print_status "WARN" "Non-local established connections detected"
            echo "$suspicious_ips" | while read -r ip; do
                echo "  -> $ip"
            done
        fi
    fi

    # Check for connections to known malicious ports
    malicious_ports=(4444 5555 6666 7777 8888 9999 31337)
    for port in "${malicious_ports[@]}"; do
        if netstat -an 2>/dev/null | grep -q ":$port "; then
            print_status "FAIL" "Connection to suspicious port: $port"
        fi
    done
}

# Check failed login attempts
check_failed_logins() {
    echo "=== Failed Login Attempts ==="

    # Check secure log for failed logins
    if [[ -f "/var/log/secure" ]]; then
        failed_root=$(grep "Failed password for root" /var/log/secure 2>/dev/null | wc -l)
        failed_invalid=$(grep "Failed password for invalid" /var/log/secure 2>/dev/null | wc -l)

        if [[ $failed_root -gt 0 ]]; then
            print_status "WARN" "$failed_root failed root login attempts found"
        else
            print_status "PASS" "No failed root login attempts"
        fi

        if [[ $failed_invalid -gt 50 ]]; then
            print_status "FAIL" "High number of invalid login attempts: $failed_invalid"
        elif [[ $failed_invalid -gt 0 ]]; then
            print_status "WARN" "$failed_invalid invalid login attempts"
        fi
    fi

    # Check lastb for failed logins
    if command -v lastb &> /dev/null; then
        recent_failed=$(lastb -a 2>/dev/null | head -20 | wc -l)
        if [[ $recent_failed -gt 0 ]]; then
            print_status "INFO" "Recent failed login attempts: $recent_failed"
        fi
    fi

    # Check for brute force indicators
    if [[ -f "/var/log/auth.log" ]]; then
        ssh_failures=$(grep "Failed password for" /var/log/auth.log 2>/dev/null | tail -100 | wc -l)
        if [[ $ssh_failures -gt 20 ]]; then
            print_status "WARN" "Potential SSH brute force: $ssh_failures recent failures"
        fi
    fi
}

# Check process security
check_process_security() {
    echo "=== Process Security ==="

    # Check for suspicious running processes
    suspicious_processes=(
        "nc"             # Netcat
        "ncat"           # Netcat
        "netcat"         # Netcat
        "socat"          # Socat
        "nmap"           # Nmap scanner
        "masscan"        # Mass scanner
        "hydra"          # Password cracker
        "john"           # John the Ripper
        "hashcat"        # Hashcat
        "aircrack"       # Aircrack
        "ettercap"       # Ettercap
        "wireshark"      # Wireshark (may be legitimate)
        "tcpdump"        # Packet sniffer
        "dsniff"         # Dsniff suite
        "minerd"         # Cryptocurrency miner
        "xmrig"          # XMRig miner
        "stratum"        # Mining stratum
    )

    suspicious_found=0
    for proc in "${suspicious_processes[@]}"; do
        if pgrep -x "$proc" &> /dev/null; then
            print_status "WARN" "Suspicious process running: $proc"
            suspicious_found=1
        fi
    done

    if [[ $suspicious_found -eq 0 ]]; then
        print_status "PASS" "No suspicious processes detected"
    fi

    # Check for processes running as root with network
    root_network_procs=$(ps aux | grep "^root" | grep -v "root\s\+[0-9]" | awk '{print $2":"$11}' | head -10)
    if [[ -n "$root_network_procs" ]]; then
        print_status "INFO" "Processes running as root with network:"
        echo "$root_network_procs" | while read -r p; do
            echo "  -> $p"
        done
    fi

    # Check CPU usage for crypto miners
    high_cpu=$(ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print $2":"$3"%"}')
    print_status "INFO" "Top CPU processes:"
    echo "$high_cpu" | while read -r p; do
        echo "  -> $p"
    done
}

# Check cron jobs security
check_cron_security() {
    echo "=== Cron Jobs Security ==="

    # Check system crons
    system_crons=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")

    for cron_dir in "${system_crons[@]}"; do
        if [[ -d "$cron_dir" ]]; then
            suspicious_crons=$(find "$cron_dir" -type f -exec grep -l "wget\|curl\|nc\|bash.*-i\|/dev/tcp\|base64" {} \; 2>/dev/null)
            if [[ -n "$suspicious_crons" ]]; then
                print_status "WARN" "Suspicious cron in $cron_dir"
                echo "$suspicious_crons" | while read -r f; do
                    echo "  -> $f"
                done
            fi
        fi
    done

    # Check user crons
    user_crons=$(find /var/spool/cron -type f 2>/dev/null)
    if [[ -n "$user_crons" ]]; then
        print_status "INFO" "User cron jobs found"
        echo "$user_crons" | while read -r f; do
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            echo "  -> $f (owner: $owner)"
        done
    else
        print_status "PASS" "No user cron jobs found"
    fi

    # Check at jobs
    at_jobs=$(atq 2>/dev/null | wc -l)
    if [[ $at_jobs -gt 0 ]]; then
        print_status "WARN" "Scheduled 'at' jobs: $at_jobs"
    else
        print_status "PASS" "No scheduled at jobs"
    fi
}

# Check startup services
check_startup_services() {
    echo "=== Startup Services ==="

    # Check systemd services
    systemctl list-unit-files --state=enabled --type=service 2>/dev/null | tail -n +2 | wc -l

    enabled_services=$(systemctl list-unit-files --state=enabled --type=service 2>/dev/null | tail -n +2 | wc -l)
    if [[ $enabled_services -gt 0 ]]; then
        print_status "INFO" "Enabled systemd services: $enabled_services"

        # Check for unnecessary network services
        network_services=("telnet.socket" "rsh.socket" "rlogin.socket" "ftp.socket" "tftp.socket")
        for svc in "${network_services[@]}"; do
            if systemctl is-enabled "$svc" &> /dev/null; then
                print_status "FAIL" "Insecure service enabled: $svc"
            fi
        done
    fi

    # Check init.d scripts
    initd_services=$(ls /etc/init.d/ 2>/dev/null | wc -l)
    if [[ $initd_services -gt 0 ]]; then
        print_status "INFO" "Init.d scripts: $initd_services"
    fi
}

# Check installed packages security
check_package_security() {
    echo "=== Package Security ==="

    # Check for known vulnerable packages
    vulnerable_packages=(
        "openssl"        # Various CVEs
        "libssl"         # SSL vulnerabilities
        "sudo"           # Sudo vulnerabilities
        "bind"           # DNS server
        "apache"         # Apache
        "nginx"          # Nginx
        "openssh"        # SSH
        "proftpd"        # FTP
        "vsftpd"         # vsFTPd
        "postfix"        # Mail
        "dovecot"        # Mail
    )

    # Check for outdated packages with known CVEs
    if command -v apt &> /dev/null; then
        # Check for security updates
        security_updates=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)
        if [[ $security_updates -gt 0 ]]; then
            print_status "FAIL" "$security_updates security updates available"
        else
            print_status "PASS" "No pending security updates"
        fi
    elif command -v yum &> /dev/null; then
        security_updates=$(yum updateinfo list security 2>/dev/null | grep -c "security")
        if [[ $security_updates -gt 0 ]]; then
            print_status "FAIL" "$security_updates security updates available"
        else
            print_status "PASS" "No pending security updates"
        fi
    fi
}

# Check system information
check_system_info() {
    echo "=== System Information ==="

    # OS info
    if [[ -f "/etc/os-release" ]]; then
        os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
        os_version=$(grep "^VERSION=" /etc/os-release | cut -d'"' -f2)
        print_status "INFO" "OS: $os_name $os_version"
    fi

    # Kernel version
    kernel=$(uname -r)
    print_status "INFO" "Kernel: $kernel"

    # Hostname
    hostname=$(hostname)
    print_status "INFO" "Hostname: $hostname"

    # System uptime
    uptime=$(uptime -p 2>/dev/null || uptime)
    print_status "INFO" "Uptime: $uptime"

    # Architecture
    arch=$(uname -m)
    print_status "INFO" "Architecture: $arch"

    # Check if running in container
    if [[ -f "/.dockerenv" ]]; then
        print_status "WARN" "Running inside Docker container"
    elif grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
        print_status "WARN" "Running inside container"
    fi

    # Check if running in VM
    if command -v systemd-detect-virt &> /dev/null; then
        virt=$(systemd-detect-virt 2>/dev/null)
        if [[ "$virt" != "none" ]]; then
            print_status "INFO" "Virtualization: $virt"
        fi
    fi
}

# Check logging configuration
check_logging_config() {
    echo "=== Logging Configuration ==="

    # Check rsyslog config
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        print_status "PASS" "rsyslog is running"

        # Check for log rotation
        if [[ -d "/etc/logrotate.d" ]]; then
            logrotate_count=$(ls /etc/logrotate.d/ 2>/dev/null | wc -l)
            print_status "INFO" "Logrotate configs: $logrotate_count"
        fi
    else
        print_status "WARN" "rsyslog is not running"
    fi

    # Check log sizes
    log_dir="/var/log"
    large_logs=$(find "$log_dir" -type f -size +100M 2>/dev/null | head -10)
    if [[ -n "$large_logs" ]]; then
        print_status "WARN" "Large log files found:"
        echo "$large_logs" | while read -r f; do
            size=$(du -h "$f" 2>/dev/null | cut -f1)
            echo "  -> $f ($size)"
        done
    fi

    # Check if logs are being written
    if [[ -w "/var/log/syslog" ]] || [[ -w "/var/log/messages" ]]; then
        print_status "PASS" "System logs are writable"
    else
        print_status "WARN" "System logs may not be writable"
    fi
}

# Check IPtables rules
check_iptables_rules() {
    echo "=== IPtables Rules ==="

    if command -v iptables &> /dev/null; then
        rules_count=$(iptables -L -n 2>/dev/null | grep -c "^Chain")
        if [[ $rules_count -gt 0 ]]; then
            print_status "INFO" "iptables chains: $rules_count"

            # Check for default policy
            input_policy=$(iptables -L INPUT -n 2>/dev/null | head -3 | grep "Policy" | awk '{print $3}')
            if [[ "$input_policy" == "DROP" ]]; then
                print_status "PASS" "INPUT chain default policy: DROP"
            elif [[ "$input_policy" == "ACCEPT" ]]; then
                print_status "WARN" "INPUT chain default policy: ACCEPT"
            fi
        else
            print_status "WARN" "No iptables rules configured"
        fi
    else
        print_status "INFO" "iptables not available"
    fi

    # Check nftables
    if command -v nft &> /dev/null; then
        if nft list ruleset 2>/dev/null | grep -q "table"; then
            print_status "INFO" "nftables is configured"
        fi
    fi
}

# Check SSL/TLS certificates
check_ssl_certificates() {
    echo "=== SSL/TLS Certificates ==="

    # Check SSL configuration in common locations
    ssl_configs=("/etc/ssl" "/etc/apache2" "/etc/nginx" "/etc/httpd")

    for conf_dir in "${ssl_configs[@]}"; do
        if [[ -d "$conf_dir" ]]; then
            # Check certificate expiry
            certs=$(find "$conf_dir" -name "*.crt" -o -name "*.pem" 2>/dev/null)
            if [[ -n "$certs" ]]; then
                while IFS= read -r cert; do
                    if [[ -f "$cert" ]]; then
                        expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                        if [[ -n "$expiry" ]]; then
                            expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
                            current_epoch=$(date +%s)
                            if [[ -n "$expiry_epoch" && "$expiry_epoch" =~ ^[0-9]+$ && -n "$current_epoch" && "$current_epoch" =~ ^[0-9]+$ ]]; then
                                days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                                if [[ $days_left -lt 30 ]]; then
                                    print_status "WARN" "Certificate $cert expires in $days_left days"
                                fi
                            else
                                print_status "WARN" "Could not calculate expiry for $cert"
                            fi
                        fi
                    fi
                done <<< "$certs"
            fi
        fi
    done
}

# Check for rootkits and system integrity
check_rootkits() {
    echo "=== Rootkit Detection ==="

    # Check for known rootkit files and directories
    rootkit_indicators=(
        "/usr/lib/libkeyutils.so"
        "/usr/lib64/libkeyutils.so"
        "/lib/libkeyutils.so"
        "/lib64/libkeyutils.so"
        "/usr/include/.../proc.h"
        "/usr/include/.../file.h"
        "/usr/include/.../proc.h"
        "/usr/include/.../file.h"
        "/dev/.lib"
        "/dev/.lib/.lib"
        "/usr/lib/.lib"
        "/usr/lib64/.lib"
        "/lib/.lib"
        "/lib64/.lib"
    )

    rootkit_found=0
    for indicator in "${rootkit_indicators[@]}"; do
        if [[ -e "$indicator" ]]; then
            print_status "FAIL" "Potential rootkit indicator found: $indicator"
            rootkit_found=1
        fi
    done

    if [[ $rootkit_found -eq 0 ]]; then
        print_status "PASS" "No known rootkit indicators detected"
    fi

    # Check for hidden processes
    hidden_procs=$(ps aux | awk '$8 ~ /<defunct>/ {print $2}' | wc -l)
    if [[ $hidden_procs -gt 0 ]]; then
        print_status "WARN" "$hidden_procs defunct processes found"
    fi

    # Check for unusual kernel modules
    if command -v lsmod &> /dev/null; then
        suspicious_modules=$(lsmod | grep -E "(diamorphine|revenant|rootkit|suterusu)" | wc -l)
        if [[ $suspicious_modules -gt 0 ]]; then
            print_status "FAIL" "Suspicious kernel modules detected"
        fi
    fi
}

# Check SUID/SGID files
check_suid_sgid() {
    echo "=== SUID/SGID Files Security ==="

    suid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    if [[ $suid_files -gt 0 ]]; then
        print_status "INFO" "$suid_files SUID/SGID files found"

        # Check for dangerous SUID binaries
        dangerous_suid=(
            "/bin/su"
            "/bin/ping"
            "/bin/ping6"
            "/usr/bin/sudo"
            "/usr/bin/su"
            "/usr/bin/passwd"
            "/usr/bin/chsh"
            "/usr/bin/chfn"
            "/usr/bin/newgrp"
            "/usr/bin/mount"
            "/usr/bin/umount"
            "/usr/bin/crontab"
        )

        for bin in "${dangerous_suid[@]}"; do
            if [[ -f "$bin" && -u "$bin" ]]; then
                print_status "INFO" "SUID binary: $bin"
            fi
        done
    else
        print_status "PASS" "No SUID/SGID files found"
    fi
}

# Check for unowned files
check_unowned_files() {
    echo "=== Unowned Files ==="

    unowned=$(find / -nouser -o -nogroup 2>/dev/null | wc -l)
    if [[ $unowned -gt 0 ]]; then
        print_status "WARN" "$unowned unowned files found"
        # Show some examples
        find / -nouser -o -nogroup 2>/dev/null | head -5 | while read -r f; do
            echo "  -> $f"
        done
    else
        print_status "PASS" "No unowned files found"
    fi
}

# Check system integrity
check_system_integrity() {
    echo "=== System Integrity ==="

    # Check for modified system files
    if command -v rpm &> /dev/null; then
        rpm_issues=$(rpm -Va 2>/dev/null | grep -E "^[SM5DLUGT]" | wc -l)
        if [[ $rpm_issues -gt 0 ]]; then
            print_status "FAIL" "$rpm_issues RPM integrity issues found"
        else
            print_status "PASS" "RPM integrity check passed"
        fi
    elif command -v dpkg &> /dev/null; then
        dpkg_issues=$(dpkg --verify 2>/dev/null | wc -l)
        if [[ $dpkg_issues -gt 0 ]]; then
            print_status "FAIL" "$dpkg_issues DPKG integrity issues found"
        else
            print_status "PASS" "DPKG integrity check passed"
        fi
    else
        print_status "INFO" "No package integrity checker available"
    fi

    # Check for unusual setuid/setgid files
    unusual_suid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | xargs ls -la 2>/dev/null | grep -v "root root" | wc -l)
    if [[ $unusual_suid -gt 0 ]]; then
        print_status "WARN" "$unusual_suid SUID/SGID files not owned by root"
    fi
}

# Check login patterns and brute force attempts
check_login_patterns() {
    echo "=== Login Patterns & Brute Force Detection ==="

    # Check for multiple failed logins from same IP
    if [[ -f "/var/log/auth.log" ]]; then
        failed_ips=$(grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -10)
        if [[ -n "$failed_ips" ]]; then
            print_status "INFO" "Failed login attempts by IP:"
            echo "$failed_ips" | while read -r line; do
                count=$(echo "$line" | awk '{print $1}')
                ip=$(echo "$line" | awk '{print $2}')
                if [[ $count -gt 20 ]]; then
                    print_status "FAIL" "Brute force attack from $ip: $count attempts"
                elif [[ $count -gt 5 ]]; then
                    print_status "WARN" "Multiple failed attempts from $ip: $count"
                fi
            done
        fi
    fi

    # Check for successful logins from unusual locations
    if [[ -f "/var/log/auth.log" ]]; then
        recent_logins=$(grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20)
        if [[ -n "$recent_logins" ]]; then
            print_status "INFO" "Recent successful logins:"
            echo "$recent_logins" | while read -r line; do
                echo "  -> $line"
            done
        fi
    fi

    # Check for root login attempts
    root_attempts=$(grep "for root" /var/log/auth.log 2>/dev/null | grep "Failed" | wc -l)
    if [[ $root_attempts -gt 0 ]]; then
        print_status "WARN" "$root_attempts failed root login attempts"
    fi
}

# Check for unusual network activity
check_network_anomalies() {
    echo "=== Network Anomalies ==="

    # Check for unusual listening ports

# Main function
main() {
    echo "========================================"
    echo "    Linux Audit Security Script"
    echo "========================================"
    echo "Started at: $(date)"
    echo ""

    check_root
    echo ""

    check_users
    echo ""

    check_permissions
    echo ""

    check_services
    echo ""

    check_ports
    echo ""

    check_firewall
    echo ""

    check_updates
    echo ""

    check_sudo
    echo ""

    check_malicious_scripts
    echo ""

    check_kernel_security
    echo ""

    check_mandatory_access_control
    echo ""

    check_ssh_security
    echo ""

    check_password_policies
    echo ""

    check_audit_daemon
    echo ""

    check_filesystem_security
    echo ""

    check_resource_limits
    echo ""

    check_usb_security
    echo ""

    check_time_sync
    echo ""

    check_pam_config
    echo ""

    check_network_connections
    echo ""

    check_failed_logins
    echo ""

    check_process_security
    echo ""

    check_cron_security
    echo ""

    check_startup_services
    echo ""

    check_package_security
    echo ""

    check_system_info
    echo ""

    check_logging_config
    echo ""

    check_iptables_rules
    echo ""

    check_ssl_certificates
    echo ""

    echo "========================================"
    echo "Audit completed at: $(date)"
    echo "========================================"
}

# Run main function
main
