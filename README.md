# Port and Vulnerability Scanner
The Python script is designed to scan IP addresses and ports for any vulnerabilities and identify any open ports. Additionally, the script has the ability to attempt to authenticate with SSH using brute force password guessing. This tool can be used to detect potential security flaws in a system and increase the security posture. With its versatile functionality, this Python script can help identify potential vulnerabilities and provide insights to improve the overall security of a system.

## Prerequisites
- Python 3.6 or higher
#### Dependencies:
- `argparse`
- `concurrent.futures`
- `ipaddress`
- `itertools`
- `matplotlib`
- `socket`
- `sys`
- `lastpass`
- `gvm`
## How it works
- Validates IP addresses and port ranges.
- Scans for vulnerabilities using the OpenVAS scanner.
- Checks if UDP and TCP ports are open.
- Attempts to authenticate with SSH using a list of passwords.
## Usage
```python
python portscanner.py [-h] -i IP_LIST -p PORT_RANGE [-k KNOCK_SEQUENCE] [-t THREADS] [-u LASTPASS_USERNAME] [-s LASTPASS_PASSWORD]
```
### Required arguments
- `-i IP_LIST`: A comma-separated list of IP addresses to scan.
- `-p PORT_RANGE`: A range of ports to scan for each IP address. Format: `start_port-end_port`.
### Optional arguments
- `-h`: Show the help message and exit.
- `-k KNOCK_SEQUENCE`: A comma-separated list of port numbers to use as a knock sequence before scanning the specified port. Default: "1111,2222,3333".
- `-t THREADS`: The number of threads to use for scanning. Default: `10`.
- `-u LASTPASS_USERNAME`: The username to use for authentication with the LastPass API. If not specified, the script will prompt for the username at runtime.
- `-s LASTPASS_PASSWORD`: The password to use for authentication with the LastPass API. If not specified, the script will prompt for the password at runtime.
## Example
To scan IP addresses 192.168.1.1 and 192.168.1.2 for open ports in the range 1-100:
```python
python portscanner.py -i 192.168.1.1,192.168.1.2 -p 1-100
```
## Notes
- Requires authentication with the `LastPass API` to retrieve credentials for scanning certain services.
- Uses the `OpenVAS` vulnerability scanner.

## Contributing
Contributions are welcome! If you have any ideas for enhancing the program or identifying bugs, kindly submit an [issue](https://github.com/TheHumanoidTyphoon/port-scanner-project/issues) or pull request on the [GitHub repository](https://github.com/TheHumanoidTyphoon/port-scanner-project).

## License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/TheHumanoidTyphoon/port-scanner-project/blob/main/LICENSE) file for details.
