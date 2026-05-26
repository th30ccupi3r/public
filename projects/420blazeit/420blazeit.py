# t0 - 2026
# current song: Darkthrone - Man tenker sitt
# nuclei -t http/technologies/blazor-webassembly-detect.yaml -u $URL

import docker
import os
import random
from colorama import init, Fore, Style
from urllib.parse import urlparse
import requests
import json 
import sys

init(autoreset=True)

def banner(text):
    colours = [
            Fore.RED,
            Fore.YELLOW,
            Fore.CYAN,
            Fore.BLUE,
            Fore.MAGENTA
            ]
    text = text.split("\n")
    for line in text:
        num = random.randint(0,4)
        print(colours[num]+line)

def log(text):
    print(Fore.BLUE+"["+Fore.RED+"+"+Fore.BLUE+"] " + Fore.MAGENTA + text)

def fingerprint(url):
    custom_dlls = []
    framework_base = url + "/_framework/"
    boot_json = framework_base + "blazor.boot.json"
    resp = requests.get(boot_json)
    if ".dll" in resp.text:
        json_data = json.loads(resp.text)
        for assembly in (json_data['resources']['assembly']):
            if not assembly.startswith("System.") and not assembly.startswith("Microsoft."):
                custom_dlls.append(assembly)
        for assembly in (json_data['resources']['lazyAssembly']):
            custom_dlls.append(assembly)
    if len(custom_dlls) > 0:
        url_parsed = urlparse(url)
        output_folder = "./output/" + url_parsed.hostname + "/dlls/"
        try:
            os.makedirs(output_folder)
        except:
            pass
        for dll in custom_dlls:
            log("downloading " + dll + "...")
            resp = requests.get(framework_base + dll)
            with open(output_folder+dll, "wb") as f:
                f.write(resp.content)

    return custom_dlls



def find_secrets():
    log("decompling DLLs and scanning for secrets...")
    cwd = os.getcwd()
    output_folder = "output"
    mount = os.path.join(cwd, output_folder)
    try:
        os.remove(mount+"/gitleaks.json")
    except:
        pass
    remote_bind = "/"+output_folder
    client = docker.from_env()
    container = client.containers.run(
            "420blazeit", 
            command=["python3", "/usr/local/bin/find_secrets.py"],
            volumes={
                mount:{"bind":remote_bind, "mode":"rw"}
                },
            detach=True,
            remove=False
            )
    result = container.wait()
    gitleaks_json = ""
    with open("./output/gitleaks.json","r") as f:
        gitleaks_json = json.load(f)
    for item in gitleaks_json:
        log("found secret in " + item["File"] + " with content:")
        print( item["Match"])
    

banner("""
@@@@@@@  @@@@@@  
  @!!   @@!  @@@ 
  @!!   @!@  !@! 
  !!:   !!:  !!! 
   :     : : :: 

No tears, please. It's a waste of good suffering.
""")

if len(sys.argv) < 2:
    log("usage: python3 420blazeit.py <target>")
    exit(-1)

dlls = fingerprint(sys.argv[1])
if len(dlls) > 0:
    find_secrets()
