import os
import getpass
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from colorama import init, Fore, Style
from tqdm import tqdm
import time

# Initialize colorama
init(autoreset=True)

# Create netmiko_debug directory if it doesn't exist
debug_folder = 'netmiko_debug'
if not os.path.exists(debug_folder):
    os.makedirs(debug_folder)

# Set up logging
logging.basicConfig(filename=f'{debug_folder}/netmiko_debug.log', level=logging.DEBUG)
logger = logging.getLogger("netmiko")

def read_ip_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip() and not line.startswith("#")]

def read_command_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def confirm_password():
    while True:
        password1 = getpass.getpass("Please enter the Device's password: ")
        password2 = getpass.getpass("Please confirm the Device's password: ")

        if password1 == password2:
            return password1
        else:
            print("Passwords do not match. Please try again.")

def confirm_execution(connection_type, host_file, command_file, username, password, enable_password):
    print(f"Connection type: {Fore.RED}{connection_type}{Style.RESET_ALL}")
    print(f"Host File: {Fore.RED}{host_file}{Style.RESET_ALL}")
    print(f"Commands File: {Fore.RED}{command_file}{Style.RESET_ALL}")
    print(f"Username: {Fore.RED}{username}{Style.RESET_ALL}")
    print(f"Password: {Fore.RED}{'********'}{Style.RESET_ALL}")  # Masking password for security
    print(f"Enable Password: {Fore.RED}{'********'}{Style.RESET_ALL}")  # Masking enable password for security

    while True:
        confirmation = input("Please confirm if the input information is correct (yes/no): ").strip().lower()
        if confirmation == 'yes':
            print(f"{Fore.RED}The Information has been confirmed{Style.RESET_ALL}")
            return True
        elif confirmation == 'no':
            return False
        else:
            print("Please enter 'yes' or 'no'.")

def connect_and_execute(device_type, ip_address, username, password, enable_password, commands, date_str, failed_ips):
    device = {
        'device_type': device_type,
        'host': ip_address,
        'username': username,
        'password': password,
        'fast_cli': False,  # Ensure Netmiko waits correctly for command output
        'session_log': f'{debug_folder}/{ip_address}_session.log'  # Optional: session log for debugging
    }

    try:
        with ConnectHandler(**device) as conn:
            # 增加延遲，確保設備準備好接收密碼
            time.sleep(1)

            # Check and handle SSH host key verification
            output = conn.send_command_timing("", strip_prompt=False, strip_command=False)
            if 'Are you sure you want to continue connecting' in output:
                output += conn.send_command_timing("yes", strip_prompt=False, strip_command=False)
                output += conn.send_command_timing(password, strip_prompt=False, strip_command=False)

            prompt = conn.find_prompt().strip()
            # Check if prompt ends with '>'
            if prompt.endswith('>'):
                conn.send_command_timing("enable")
                conn.send_command_timing(enable_password)

            prompt = conn.find_prompt().strip()  # Get the new prompt after enabling
            hostname = prompt.split('#')[0]
            output_folder = date_str
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)
            output_file_name = f"{output_folder}/{hostname}_{date_str}.txt"

            with open(output_file_name, 'w') as output_file:
                for command in commands:
                    # Send an Enter key before each command
                    conn.send_command_timing("", strip_prompt=False, strip_command=False)
                    logger.debug(f"Sending command '{command}' to {hostname}")
                    full_command = f"{prompt} {command}\n"
                    output_file.write(full_command)  # Write the full command with prompt
                    command_output = conn.send_command(command, expect_string=r'#', delay_factor=0.5, max_loops=150, read_timeout=75)
                    logger.debug(f"Output of command '{command}':\n{command_output}")
                    output_file.write(f"{command_output.strip()}\n")  # Write the output, removing trailing newline to keep on the same line

            print(f"Output of {hostname} saved to {output_file_name}")
    except NetmikoTimeoutException:
        error_message = "Timeout error"
        logger.error(f"Timeout error with host {ip_address}")
        print(f"Timeout error with host {ip_address}")
        failed_ips.append((ip_address, error_message))  # Record failed IP and short error message
    except NetmikoAuthenticationException:
        error_message = "Authentication error"
        logger.error(f"Authentication error with host {ip_address}")
        print(f"Authentication error with host {ip_address}")
        failed_ips.append((ip_address, error_message))  # Record failed IP and short error message
    except Exception:
        error_message = "Unknown error"
        logger.error(f"Error with host {ip_address}")
        print(f"Error with host {ip_address}")
        failed_ips.append((ip_address, error_message))  # Record failed IP and short error message

def write_failed_ips(failed_ips):
    with open("ConnectionFail.txt", 'w') as fail_file:
        for ip, reason in failed_ips:
            fail_file.write(f"{ip} | \"{reason}\"\n")

if __name__ == "__main__":
    start_time = datetime.now()  # Record start time

    connection_type = input("Please choose connection type (telnet/ssh): ").strip().lower()
    device_type = 'cisco_ios_telnet' if connection_type == 'telnet' else 'cisco_ios_ssh'
    host_file = input("Please enter the name of the txt file containing IP addresses: ").strip()
    command_file = input("Please enter the name of the txt file containing Commands: ").strip()
    username = input("Please enter the Device's username: ").strip()
    password = confirm_password()
    enable_password = getpass.getpass("Please enter the Device's enable password: ").strip()

    if not confirm_execution(connection_type, host_file, command_file, username, password, enable_password):
        print("Execution aborted.")
        exit()

    ips = read_ip_file(host_file)
    commands = read_command_file(command_file)
    date_str = datetime.now().strftime("%Y%m%d")
    failed_ips = []

    max_threads = 30
    # Add progress bar
    with ThreadPoolExecutor(max_workers=min(max_threads, len(ips))) as executor:
        futures = []
        with tqdm(total=len(ips), desc="Processing") as pbar:  # Initialize tqdm progress bar
            for ip in ips:
                future = executor.submit(connect_and_execute, device_type, ip, username, password, enable_password, commands, date_str, failed_ips)
                futures.append(future)
            
            # Update progress bar as tasks complete
            for future in as_completed(futures):
                pbar.update(1)  # Update progress bar by one step

    # Write failed IPs to a file with reasons
    if failed_ips:
        write_failed_ips(failed_ips)
        print(f"{Fore.RED}Connection failures saved to ConnectionFail.txt{Style.RESET_ALL}")

    # Calculate success rate
    total_ips = len(ips)
    successful_connections = total_ips - len(failed_ips)
    success_rate = (successful_connections / total_ips) * 100

    end_time = datetime.now()  # Record end time
    total_time = end_time - start_time
    hours, remainder = divmod(total_time.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Total execution time: {Fore.RED}{int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds{Style.RESET_ALL}")
    print(f"Total expected files: {Fore.RED}{total_ips}{Style.RESET_ALL}")
    print(f"Total files created: {Fore.RED}{successful_connections}{Style.RESET_ALL}")
    print(f"Failed files: {Fore.RED}{len(failed_ips)}{Style.RESET_ALL}")
    print(f"Success rate: {Fore.RED}{success_rate:.2f}%{Style.RESET_ALL}")
