# IOC Defanger / Refanger

Converts IOCs (URLs, IPs, domains, emails) between "live" and "defanged" form — the standard SOC practice of writing `hxxp://185[.]220[.]101[.]7` instead of a real clickable URL when documenting a malicious indicator in a ticket, report, or chat tool, so it can't be accidentally clicked or auto-fetched by a link-preview bot.

## Usage

```bash
python defang.py defang "http://185.220.101.7/payload.exe"
python defang.py refang "hxxp://185[.]220[.]101[.]7/payload.exe"
python defang.py defang --file iocs.txt    # batch mode, one IOC per line
```

## Example

```
$ python defang.py defang "http://185.220.101.7/payload.exe"
hxxp://185[.]220[.]101[.]7/payload[.]exe

$ python defang.py refang "hxxp://185[.]220[.]101[.]7/payload.exe"
http://185.220.101.7/payload.exe

$ python defang.py defang "malicious-sender@evil-domain.com"
malicious-sender[at]evil-domain[.]com
```

## Why this matters

Pasting a live malicious URL into Slack, Teams, Jira, or email risks:
- Someone accidentally clicking it
- The chat platform's own link-preview bot fetching it (which can tip off the attacker that it's been discovered, or trigger the payload)
- Email/URL filters flagging or blocking the *message itself* as malicious

Defanging (`http` → `hxxp`, `.` → `[.]`) neutralizes all of that while keeping the indicator fully readable and copy-pasteable by a human — and `refang` reverses it instantly when you need to feed the real value into a tool (grep, a SIEM query, a blocklist).
