FROM debian:bookworm
RUN apt -y update && apt -y install wget git python3
COPY find_secrets.py /usr/local/bin
RUN wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.30.1_linux_x64.tar.gz \
 && tar -xzf gitleaks_8.30.1_linux_x64.tar.gz \
 && mv gitleaks /usr/local/bin/ \
 && chmod +x /usr/local/bin/gitleaks \
 && rm gitleaks_8.30.1_linux_x64.tar.gz
RUN wget -q https://packages.microsoft.com/debian/12/prod/pool/main/p/packages-microsoft-prod/packages-microsoft-prod_1.1-debian12_all.deb
RUN dpkg -i packages-microsoft-prod_1.1-debian12_all.deb
RUN apt -y update
RUN apt -y install dotnet-sdk-10.0
WORKDIR /
RUN git clone https://github.com/icsharpcode/ILSpy
WORKDIR /ILSpy
RUN git submodule update --init --recursive
RUN git checkout v8.2
RUN apt install -y dotnet-sdk-10.0 powershell dotnet-runtime-6.0
RUN dotnet build /ILSpy/ICSharpCode.ILSpyCmd/ICSharpCode.ILSpyCmd.csproj
