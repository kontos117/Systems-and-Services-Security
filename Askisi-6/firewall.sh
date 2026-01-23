#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi

    if [ "$1" = "-config"  ]; then
        # Configure adblock rules based on domain names and IPs of $config file.
        
        # check if config file exists
        if [ ! -f "$config" ]; then
            printf "Configuration file '$config' not found.\n"
            exit 1
        fi

        printf "Configuring rules from $config... (this may take a moment)\n"

        # loop through each line in the config file
        # process each domain in the background (&) to speed up DNS lookups
        for name in $(cat "$config"); do
            (
                # resolve and Block IPv4
                # 'host -t A' gets IPv4. grep finds the line, awk grabs the IP (4th word)
                for ip in $(host -t A "$name" | grep "has address" | awk '{print $4}'); do
                    # Add rule to reject traffic from this IP
                    iptables -A INPUT -s "$ip" -j REJECT
                done

                # resolve and Block IPv6
                # 'host -t AAAA' gets IPv6. IPv6 output format is slightly different (IP is 5th word)
                for ip6 in $(host -t AAAA "$name" | grep "has IPv6 address" | awk '{print $5}'); do
                    # add rule to reject traffic from this IP
                    ip6tables -A INPUT -s "$ip6" -j REJECT
                done
            ) & 
        done

        # wait for all background DNS lookups/iptables commands to finish
        wait
        printf "Firewall configuration complete.\n"

    elif [ "$1" = "-save"  ]; then
        # Save rules to $rulesV4/$rulesV6 files.
        printf "Saving rules to $rulesV4 and $rulesV6...\n"
        iptables-save > "$rulesV4"
        ip6tables-save > "$rulesV6"
        printf "Rules saved.\n"

    elif [ "$1" = "-load"  ]; then
        # Load rules from $rulesV4/$rulesV6 files.
        if [ -f "$rulesV4" ] && [ -f "$rulesV6" ]; then
            printf "Loading rules from files...\n"
            iptables-restore < "$rulesV4"
            ip6tables-restore < "$rulesV6"
            printf "Rules loaded.\n"
        else
            printf "Save files not found. Run -save first.\n"
        fi

    elif [ "$1" = "-reset"  ]; then
        # Reset IPv4/IPv6 rules to default settings (i.e. accept all).
        printf "Resetting all rules to default (ACCEPT)...\n"
        
        # IPv4 Flush and Reset
        iptables -F         # Flush all rules
        iptables -X         # Delete user-defined chains
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT

        # IPv6 Flush and Reset
        ip6tables -F
        ip6tables -X
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        
        printf "Reset complete.\n"

    elif [ "$1" = "-list"  ]; then
        # List IPv4/IPv6 current rules.
        printf "=== IPv4 Rules ===\n"
        # -v: verbose (shows packet counts), -n: numeric (no DNS lookup, faster)
        iptables -L -v -n
        printf "\n=== IPv6 Rules ===\n"
        ip6tables -L -v -n

    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0