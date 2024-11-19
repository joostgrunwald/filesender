#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to append audit keys without duplicates
append_audit_keys() {
    echo "Appending audit keys to /var/ossec/etc/lists/audit-keys..."
    AUDIT_KEYS_FILE="/var/ossec/etc/lists/audit-keys"
    AUDIT_KEYS=(
        "passwd_access:passwd"
        "shadow_access:shadow"
        "history_access:history"
        "ssh_access:ssh"
    )

    for key in "${AUDIT_KEYS[@]}"; do
        if ! sudo grep -Fxq "$key" "$AUDIT_KEYS_FILE"; then
            echo "$key" | sudo tee -a "$AUDIT_KEYS_FILE" > /dev/null
            echo "Added audit key: $key"
        else
            echo "Audit key already exists: $key"
        fi
    done
}

append_local_rules() {
    echo "Appending custom rules to /var/ossec/etc/rules/local_rules.xml..."

    LOCAL_RULES_FILE="/var/ossec/etc/rules/local_rules.xml"

    # Backup the original local_rules.xml
    sudo cp "$LOCAL_RULES_FILE" "${LOCAL_RULES_FILE}.bak"

    # Check if the group already exists
    if ! sudo grep -q '<group name="cred_access,">' "$LOCAL_RULES_FILE"; then
        sudo tee -a "$LOCAL_RULES_FILE" > /dev/null << 'EOF'
<group name="cred_access,">
  <!--Detect access to offline password storing files-->
  <rule id="100110" level="7">
    <if_sid>80700</if_sid>
    <list field="audit.key" lookup="match_key_value" check_value="passwd">etc/lists/audit-keys</list>
    <description>File access - The file $(audit.file.name) was accessed</description>
    <group>audit_command,</group>
    <mitre>
      <id>T1003.008</id>
    </mitre>
  </rule>
  <rule id="100120" level="10">
    <if_sid>80700</if_sid>
    <list field="audit.key" lookup="match_key_value" check_value="shadow">etc/lists/audit-keys</list>
    <description>Possible adversary activity - $(audit.file.name) was accessed</description>
    <group>audit_command,</group>
    <mitre>
      <id>T1003.008</id>
    </mitre>
  </rule>
  <!--Detecting suspicious activities related to unsecured credentials -->
  <rule id="100131" level="0">
    <if_sid>80700</if_sid>
    <list field="audit.key" lookup="match_key_value" check_value="ssh">etc/lists/audit-keys</list>
    <description>Possible adversary activity - $(audit.file.name) was accessed</description>
    <group>audit_command,</group>
  </rule>
  <rule id="100132" level="0">
    <if_sid>80700</if_sid>
    <list field="audit.key" lookup="match_key_value" check_value="history">etc/lists/audit-keys</list>
    <description>Possible adversary activity - $(audit.file.name) was accessed</description>
    <group>audit_command,</group>
  </rule>
  <rule id="100133" level="0">
    <if_sid>80700</if_sid>
    <field name="audit.exe" type="pcre2">/usr/bin/*grep</field>
    <field name="audit.execve.a2">cred|password|login</field>
    <description>Possible adversary activity - $(audit.file.name) was accessed</description>
    <group>audit_command,</group>
  </rule>
  <rule id="100130" level="10">
    <if_sid>100131, 100132, 100133</if_sid>
    <description>Possible adversary activity - searching for previously used credentials in system files</description>
    <group>audit_command,</group>
    <mitre>
      <id>T1552.001</id>
    </mitre>
  </rule>
</group>
EOF
        echo "Custom rules appended to local_rules.xml."
    else
        echo "Custom rules already exist in local_rules.xml."
    fi
}

# Function to create comm_persist_tech_rules.xml with SSH authorized keys persistence rules
create_comm_persist_tech_rules() {
    echo "Creating /var/ossec/etc/rules/comm_persist_tech_rules.xml with SSH authorized keys persistence rules..."

    RULES_FILE="/var/ossec/etc/rules/comm_persist_tech_rules.xml"

if [ ! -f "$RULES_FILE" ]; then
    sudo bash -c "cat << 'EOF' > $RULES_FILE
<group name=\"common_persistence_techniques,sshd,\">
  <rule id=\"100100\" level=\"10\">
    <if_sid>554</if_sid>
    <field name=\"file\" type=\"pcre2\">\\/authorized_keys$</field>
    <description>SSH authorized_keys file \"\$(file)\" has been added</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
  </rule>
  <rule id=\"100101\" level=\"10\">
    <if_sid>550</if_sid>
    <field name=\"file\" type=\"pcre2\">\\/authorized_keys$</field>
    <description>SSH authorized_keys file \"\$(file)\" has been modified</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
  </rule>
  <rule id=\"100102\" level=\"10\">
    <if_sid>550</if_sid>
    <field name=\"file\" type=\"pcre2\">\\/sshd_config$</field>
    <description>SSH config file \"\$(file)\" has been modified</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
  </rule>
</group>
EOF"
fi
}

# Function to create additional persistence technique rules
create_common_persist_techniques_rules() {
    echo "Creating /var/ossec/etc/rules/common_persist_techniques_additional_rules.xml with Unix shell config persistence rules..."

    RULES_FILE="/var/ossec/etc/rules/common_persist_techniques_additional_rules.xml"

if [ ! -f "$RULES_FILE" ]; then
    sudo bash -c "cat << 'EOF' > $RULES_FILE
<group name=\"common_persistence_techniques,\">
  <rule id=\"100120\" level=\"10\">
    <if_sid>554</if_sid>
    <field name=\"file\" type=\"pcre2\">\\/etc\\/profile$|\\/etc/profile.d\\/|\\/etc\\/bash.bashrc$|\\/etc\\/bash.bash_logout$|\\.bash_profile$|\\.bash_login$|\\.profile$|\\.bash_profile$|\\.bashrc$|\\.bash_logout$</field>
    <description>Unix shell config \"\$(file)\" has been added</description>
    <mitre>
      <id>T1546.004</id>
    </mitre>
  </rule>
  <rule id=\"100121\" level=\"10\">
    <if_sid>550</if_sid>
    <field name=\"file\" type=\"pcre2\">\\/etc\\/profile$|\\/etc/profile.d\\/|\\/etc\\/bash.bashrc$|\\/etc\\/bash.bash_logout$|\\.bash_profile$|\\.bash_login$|\\.profile$|\\.bash_profile$|\\.bashrc$|\\.bash_logout$</field>
    <description>Unix shell config \"\$(file)\" has been modified</description>
    <mitre>
      <id>T1546.004</id>
    </mitre>
  </rule>
</group>
EOF"
fi
}

# Function to restart wazuh-manager service
restart_wazuh_manager() {
    echo "Restarting wazuh-manager service..."
    sudo systemctl restart wazuh-manager
}

# Main execution flow
main() {
    append_audit_keys
    append_local_rules
    create_comm_persist_tech_rules
    create_common_persist_techniques_rules
    restart_wazuh_manager
    echo "Wazuh Manager configuration completed successfully."
}

# Run the main function
main
