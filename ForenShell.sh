#!/bin/bash
# ForenShell - Automated Forensic Toolkit
# Version: 1.0.0
# Author: Ben Deshet
# Description: A toolkit for analyzing files using Linux forensic tools.

# Colors for better readability
GREEN="\033[1;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

echo -e "${CYAN}Welcome to ForenShell - The Automated Forensic Toolkit${RESET}"


function ROOT_CHECK() {
    if [ "$USER" != "root" ]; then
        echo -e "${RED}To run this tool, you have to be logged in as root.${RESET}"
        echo -e "${YELLOW}Switch to root? [y/n]${RESET}"
        read -r yesorno
        if [ "$yesorno" = "y" ]; then
            echo -e "${GREEN}Switching to root...${RESET}"
            script_path=$(realpath "$0")
            exec sudo su -c "$script_path" root "$@"
        else
            echo -e "${RED}Exiting...${RESET}"
            exit
        fi
    fi
}

ROOT_CHECK
start_time=$(date +%s) # Record the start time

function FILE_CHECK {
    echo -e "${CYAN}Please enter the filename you want to analyze:${RESET}"
    read file_to_check
    if [ -f "$file_to_check" ]; then
        echo -e "${GREEN}[+] Preparing to start a scan on the file $file_to_check within 3 seconds...${RESET}"
        sleep 3
    else
        echo -e "${RED}[-] The file does not exist.${RESET}"
        FILE_CHECK
    fi
}
FILE_CHECK
# Installing the forensics tools
function FORENSICS_TOOLS {
    echo -e "${BLUE}[+] Checking for needed forensic tools...${RESET}"
    sleep 2
    tools=("binwalk" "bulk_extractor" "foremost" "strings")
    log_file="tool_installation.log"

    # Clear previous log file
    > "$log_file"

    for tool in "${tools[@]}"; do
        echo -e "${CYAN}[+] Checking if $tool is installed...${RESET}"
        which "$tool" &>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] $tool is already installed on your machine.${RESET}"
        else
            echo -e "${YELLOW}[+] $tool is not installed. Attempting installation...${RESET}"
            sudo apt-get update -y >> "$log_file" 2>&1
            sudo apt-get install -y "$tool" >> "$log_file" 2>&1
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] Successfully installed $tool.${RESET}"
            else
                echo -e "${RED}[-] Failed to install $tool. Check $log_file for details.${RESET}"
            fi
        fi
        sleep 1
    done

    # Volatility installation
    echo -e "${CYAN}[+] Downloading Volatility executable...${RESET}"
    wget "https://drive.usercontent.google.com/u/0/uc?id=1KnqmGLzVAFRE91cUz7b5aA6ejATHJGjd&export=download" -O volatility >> "$log_file" 2>&1
    if [ $? -eq 0 ]; then
        chmod +x volatility
        echo -e "${GREEN}[+] Successfully downloaded and prepared Volatility.${RESET}"
    else
        echo -e "${RED}[-] Failed to download Volatility. Check $log_file for details.${RESET}"
    fi

    echo -e "${GREEN}[+] Tool installation process completed.${RESET}"
    echo -e "${YELLOW}[!] Check $log_file for detailed logs.${RESET}"
}
FORENSICS_TOOLS

function ANALYZE {
    echo -e "${CYAN}[+] Starting to analyze the given file.${RESET}"
    mkdir binwalk bulk_extractor foremost strings volatility > /dev/null 2>&1
    for i in "$file_to_check"; do
        echo -e "${GREEN}[+] Analyzing $file_to_check using binwalk...${RESET}"
        mkdir ./binwalk/$file_to_check > /dev/null 2>&1
        binwalk "$file_to_check" > ./binwalk/$file_to_check/binwalk_results.log
        sleep 2

        echo -e "${GREEN}[+] Analyzing $file_to_check using bulk_extractor...${RESET}"
        mkdir ./bulk_extractor/$file_to_check > /dev/null 2>&1
        bulk_extractor -o ./bulk_extractor/$file_to_check "$file_to_check" > ./bulk_extractor/$file_to_check/bulk_extractor_results.log
        sleep 2

        echo -e "${GREEN}[+] Analyzing $file_to_check using foremost...${RESET}"
        mkdir ./foremost/$file_to_check > /dev/null 2>&1
        foremost -o ./foremost/$file_to_check "$file_to_check" > /dev/null 2>&1
        sleep 2

        echo -e "${GREEN}[+] Analyzing $file_to_check using strings...${RESET}"
        mkdir ./strings/$file_to_check > /dev/null 2>&1
        strings "$file_to_check" > ./strings/$file_to_check/strings_results.log
    done

    if [ -f "./bulk_extractor/$file_to_check/packets.pcap" ]; then
        echo -e "${YELLOW}[+] Found Network File -> Saved into ./bulk_extractor/$file_to_check/packets.pcap [Size: $(ls -lh ./bulk_extractor/$file_to_check/ | grep packets.pcap | awk '{print $5}')]${RESET}"
    fi
    echo -e "${GREEN}[+] Successfully finished analyzing the file $file_to_check.${RESET}"
    sleep 3
}
ANALYZE

function STRINGS {
    # List of popular keywords to search for (You can add or edit)
    keywords=(
        "http" "https" "ftp" "ssh" "smtp" "imap" "pop3" "dns" "telnet"
        "cmd" "powershell" "bash" "zsh" "sh" "terminal"
        "admin" "root" "superuser" "sysadmin" "sudo"
        "password" "passwd" "pwd" "secret" "token" "key"
        "login" "auth" "authentication" "username" "user" "profile"
    )

    output_file="./strings/$file_to_check/extracted_strings.log"
    > "$output_file"

    total_keywords=${#keywords[@]}
    echo "------------------------------------------------------"
    echo -e "${CYAN}[+] Extracting strings from $file_to_check using ${total_keywords} keywords...${RESET}"

    for i in "${!keywords[@]}"; do
        keyword=${keywords[$i]}
        printf "\r${YELLOW}[+] Processing keyword [$((i + 1))/$total_keywords]: %-20s${RESET}" "$keyword"
        strings "$file_to_check" | grep -i "$keyword" >> "$output_file"
    done

    echo -e "\n${GREEN}[+] Strings extraction complete. Results saved in $output_file.${RESET}"
    echo "------------------------------------------------------"
}
STRINGS

function VOLATILITY {
    echo -e "${CYAN}[+] Starting Volatility...${RESET}"
    mkdir ./volatility_results/ > /dev/null 2>&1 && mkdir ./volatility_results/$file_to_check/ > /dev/null 2>&1
    if [ -z "$(sudo ./volatility -f $file_to_check imageinfo 2>/dev/null | grep 'Suggested Profile' | grep 'No suggestion')" ]; then
        echo -e "${GREEN}[+] Running Volatility on $file_to_check...${RESET}"
        profile=$(sudo ./volatility -f $file_to_check imageinfo 2>/dev/null | grep 'Suggested Profile' | awk -F ': ' '{print $2}' | awk -F ',' '{print $1}' | xargs)
        echo -e "${CYAN}[+] Using Detected Profile: $profile${RESET}"

        vol_command=("pslist" "pstree" "psscan" "dlllist" "cmdscan" "consoles" "connections" "connscan" "hivelist" "hivescan")
        for command in "${vol_command[@]}"; do
            echo -e "${GREEN}[+] Running Volatility $command on $file_to_check...${RESET}"
            sudo ./volatility -f "$file_to_check" --profile="$profile" "$command" 2>/dev/null | grep -v "Volatility Foundation Volatility Framework" >> ./volatility_results/$file_to_check/volatility_results.log
            if [ $? != 0 ]; then
                echo -e "${RED}[-] The profile $profile does not support $command, skipping...${RESET}"
            fi
        done
    else
        echo -e "${RED}[-] Cannot run Volatility on $file_to_check as it is not a memory file.${RESET}"
    fi
    echo -e "${GREEN}[+] Volatility analysis complete. Results saved to ./volatility_results/$file_to_check/volatility_results.log${RESET}"
}
VOLATILITY
function GENERATE_REPORT {
    echo -e "${CYAN}[+] Generating general report for $file_to_check...${RESET}"

    # Define the general report file
    report_file="general_report_$file_to_check.log"
    > "$report_file" # Clear the file if it already exists

    # Write initial report details
    echo "------------------------------------------------------" >> "$report_file"
    echo "General Report for: $file_to_check" >> "$report_file"
    echo "Generated on: $(date)" >> "$report_file"
    echo "------------------------------------------------------" >> "$report_file"

    # Tool Installation Log
    if [ -f "tool_installation.log" ]; then
        echo -e "${GREEN}[+] Adding tool installation log to the report...${RESET}"
        echo "Tool Installation Log:" >> "$report_file"
        cat "tool_installation.log" >> "$report_file"
    else
        echo -e "${RED}[-] Tool installation log not available.${RESET}"
        echo "[!] Tool installation log not available." >> "$report_file"
    fi

    # Binwalk Results
    binwalk_log="./binwalk/$file_to_check/binwalk_results.log"
    if [ -f "$binwalk_log" ]; then
        echo -e "${GREEN}[+] Adding binwalk results...${RESET}"
        echo "Binwalk Results:" >> "$report_file"
        cat "$binwalk_log" >> "$report_file"
    else
        echo -e "${RED}[-] Binwalk results not available.${RESET}"
        echo "[!] Binwalk results not available." >> "$report_file"
    fi

    # Bulk Extractor Results
    bulk_extractor_log="./bulk_extractor/$file_to_check/bulk_extractor_results.log"
    if [ -f "$bulk_extractor_log" ]; then
        echo -e "${GREEN}[+] Adding bulk_extractor results...${RESET}"
        echo "Bulk Extractor Results:" >> "$report_file"
        cat "$bulk_extractor_log" >> "$report_file"
    else
        echo -e "${RED}[-] Bulk Extractor results not available.${RESET}"
        echo "[!] Bulk Extractor results not available." >> "$report_file"
    fi

    # Foremost Results
    foremost_dir="./foremost/$file_to_check"
    if [ -d "$foremost_dir" ]; then
        echo -e "${GREEN}[+] Adding foremost results...${RESET}"
        echo "Foremost Recovered Files:" >> "$report_file"
        ls -lh "$foremost_dir" >> "$report_file"
    else
        echo -e "${RED}[-] Foremost results not available.${RESET}"
        echo "[!] Foremost results not available." >> "$report_file"
    fi

    # Strings Results
    strings_log="./strings/$file_to_check/strings_results.log"
    strings_log_extracted="./strings/$file_to_check/extracted_strings.log"
    if [ -f "$strings_log_extracted" ]; then
        echo -e "${GREEN}[+] Adding extracted strings results...${RESET}"
        echo "Extracted Strings Results:" >> "$report_file"
        cat "$strings_log_extracted" >> "$report_file"
    else
        echo -e "${RED}[-] Extracted strings results not available.${RESET}"
        echo "[!] Extracted strings results not available." >> "$report_file"
    fi

    # Volatility Results
    volatility_log="./volatility_results/$file_to_check/volatility_results.log"
    if [ -f "$volatility_log" ]; then
        echo -e "${GREEN}[+] Adding volatility results...${RESET}"
        echo "Volatility Results:" >> "$report_file"
        cat "$volatility_log" >> "$report_file"
    else
        echo -e "${RED}[-] Volatility results not available.${RESET}"
        echo "[!] Volatility results not available." >> "$report_file"
    fi

    # Error Log (if any)
    error_log="./update_packages.log"
    if [ -f "$error_log" ]; then
        echo -e "${YELLOW}[+] Adding error log details...${RESET}"
        echo "Error Log Details:" >> "$report_file"
        cat "$error_log" >> "$report_file"
    else
        echo -e "${RED}[-] Error log not available.${RESET}"
        echo "[!] Error log not available." >> "$report_file"
    fi

    # Total Time and Files Created
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    total_files_created=$(find . -type f | wc -l)

    # Add summary to the report
    echo "------------------------------------------------------" >> "$report_file"
    echo "Summary:" >> "$report_file"
    echo "Total Scan Duration: ${duration}s" >> "$report_file"
    echo "Total Files Created During Analysis: $total_files_created" >> "$report_file"
    echo "------------------------------------------------------" >> "$report_file"

    # Output summary to the terminal
    echo -e "${GREEN}[+] General report generated successfully.${RESET}"
    echo -e "${CYAN}Report File: $report_file${RESET}"
    echo "------------------------------------------------------"
}

GENERATE_REPORT
