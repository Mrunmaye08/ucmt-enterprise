import socket
import platform
import getpass
import uuid
import datetime

def get_system_info():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    os_version = platform.platform()
    user = getpass.getuser()
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                    for ele in range(0,8*6,8)][::-1])

    return {
        "hostname": hostname,
        "ip": ip,
        "os": os_version,
        "user": user,
        "mac": mac
    }

def scan_open_ports():
    common_ports = {
        21:"FTP",
        22:"SSH",
        23:"Telnet",
        25:"SMTP",
        53:"DNS",
        80:"HTTP",
        110:"POP3",
        139:"NetBIOS",
        143:"IMAP",
        443:"HTTPS",
        445:"SMB",
        3389:"RDP"
    }

    open_ports = []

    host = socket.gethostname()
    ip = socket.gethostbyname(host)

    for port,service in common_ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append({
                "port": port,
                "service": service,
                "risk": "Potentially Exposed Service"
            })
        s.close()

    return open_ports