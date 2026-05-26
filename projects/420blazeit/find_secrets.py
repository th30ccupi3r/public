from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os

def decompile(dll):
    str_dll = str(dll)
    command = "dotnet /ILSpy/ICSharpCode.ILSpyCmd/bin/Debug/net6.0/ilspycmd.dll " + str_dll
    src_code = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    output_file = str_dll
    output_file = output_file.replace(".dll",".cs")
    fp = open(output_file, "w")
    fp.write(src_code.stdout)
    fp.close()



def main():
    directory = Path("/output")
    dlls = []
    for item in directory.rglob("*.dll"):
        if item.is_file():
            full_path = item.resolve()
            dlls.append(full_path)
    for dll in dlls:
        decompile(dll)
    os.chdir("/output")
    command = "gitleaks dir -f json -r gitleaks.json"
    subprocess.run(command, shell=True)

if __name__ == "__main__":
                main()
