    #!/bin/bash

    # Exit immediately if a command exits with a non-zero status
    set -e

    # Function to install packages if they are not already installed
    install_packages() {
        echo "Checking and installing required packages..."
        REQUIRED_PACKAGES=("auditd" "audispd-plugins")
        for package in "${REQUIRED_PACKAGES[@]}"; do
            if ! dpkg -l | grep -qw "$package"; then
                echo "Installing $package..."
                sudo apt-get update
                sudo apt-get install -y "$package"
            else
                echo "$package is already installed."
            fi
        done
    }

    # Function to start and enable auditd service
    start_enable_auditd() {
        echo "Starting and enabling auditd service..."
        sudo systemctl start auditd
        sudo systemctl enable auditd
    }

    # Function to append audit rules without duplicates
    append_audit_rules() {
        echo "Appending audit rules to /etc/audit/rules.d/audit.rules..."
        
        AUDIT_RULES=(
            "-a exit,always -F arch=b64 -F auid!=-1 -F euid!=0 -S execve -k audit-wazuh-c"
            "-a exit,always -F arch=b64 -F path=/etc/shadow -F auid!=-1 -F euid!=0 -F perm=r -k shadow_access"
            "-a exit,always -F arch=b64 -F path=/etc/passwd -F auid!=-1 -F euid!=0 -F perm=r -k passwd_access"
            "-a exit,always -F arch=b64 -F path=/home/azureuser/.bash_history -F auid!=-1 -F euid!=0 -F perm=r -k history_access"
            "-a exit,always -F arch=b64 -F dir=/home/azureuser/.ssh/ -F auid!=-1 -F euid!=0 -F perm=r -k ssh_access"
        )

        AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"

        for rule in "${AUDIT_RULES[@]}"; do
            if ! sudo grep -Fxq -- "$rule" "$AUDIT_RULES_FILE"; then
                echo "$rule" | sudo tee -a "$AUDIT_RULES_FILE" > /dev/null
                echo "Added rule: $rule"
            else
                echo "Rule already exists: $rule"
            fi
        done
        
        # Reload audit rules
        sudo augenrules --load
    }
    # Function to append configurations to /var/ossec/etc/ossec.conf
    append_ossec_conf() {
        echo "Updating /var/ossec/etc/ossec.conf with audit log and syscheck configurations..."

        OSSEC_CONF="/var/ossec/etc/ossec.conf"

        # Backup the original ossec.conf
        sudo cp "$OSSEC_CONF" "${OSSEC_CONF}.bak"
        echo "Backup of ossec.conf created at ${OSSEC_CONF}.bak"

        # Append audit log configuration if not present
        if ! sudo grep -q '<log_format>audit</log_format>' "$OSSEC_CONF"; then
            sudo sed -i '/<\/ossec_config>/i\
    <localfile>\
        <log_format>audit</log_format>\
        <location>/var/log/audit/audit.log</location>\
    </localfile>' "$OSSEC_CONF"
            echo "Appended audit log configuration."
        else
            echo "Audit log configuration already exists."
        fi

        # Define syscheck directories to add
        directories=(
            "/root/.ssh/"
            "/home/*/.ssh/"
            "/var/*/.ssh/"
            "/etc/ssh/sshd_config"
            "/etc/"
            "/home/*/.bash_profile"
            "/home/*/.bash_login"
            "/home/*/.profile"
            "/home/*/.bashrc"
            "/home/*/.bash_logout"
            "/root/.bash_profile"
            "/root/.bash_login"
            "/root/.profile"
            "/root/.bashrc"
            "/root/.bash_logout"
        )

        # Function to append syscheck directories if not present
        append_syscheck_directories() {
            for dir in "${directories[@]}"; do
                # Escape forward slashes for grep
                escaped_dir=$(echo "$dir" | sed 's/\//\\\//g')
                if ! sudo grep -q "<directories check_all=\"yes\" realtime=\"yes\">$dir</directories>" "$OSSEC_CONF"; then
                    sudo sed -i "/<syscheck>/a\
        <directories check_all=\"yes\" realtime=\"yes\">$dir</directories>" "$OSSEC_CONF"
                    echo "Appended syscheck directory: $dir"
                else
                    echo "Syscheck directory already exists: $dir"
                fi
            done
        }

        append_syscheck_directories

        # Append monitoring configuration for Downloads folder of the current user
        USER_DOWNLOADS_DIR="/home/$USER/"
        if [ -d "$USER_DOWNLOADS_DIR" ]; then
            # Escape forward slashes for grep
            escaped_dir=$(echo "$USER_DOWNLOADS_DIR" | sed 's/\//\\\//g')
            if ! sudo grep -q "<directories check_all=\"yes\" realtime=\"yes\">$USER_DOWNLOADS_DIR</directories>" "$OSSEC_CONF"; then
                sudo sed -i "/<syscheck>/a\
        <directories check_all=\"yes\" realtime=\"yes\">$USER_DOWNLOADS_DIR</directories>" "$OSSEC_CONF"
                echo "Appended syscheck directory for Home folder: $USER_DOWNLOADS_DIR"
            else
                echo "Syscheck directory already exists for Home folder: $USER_DOWNLOADS_DIR"
            fi
        else
            echo "Home folder does not exist for the current user: $USER_DOWNLOADS_DIR"
        fi
    }

    # Function to restart wazuh-agent service
    restart_wazuh_agent() {
        echo "Restarting wazuh-agent service..."
        sudo systemctl restart wazuh-agent
    }

    # Main execution flow
    main() {
        install_packages
        start_enable_auditd
        append_audit_rules
        append_ossec_conf
        restart_wazuh_agent
        echo "Wazuh Agent configuration completed successfully."
    }

    # Run the main function
    main
