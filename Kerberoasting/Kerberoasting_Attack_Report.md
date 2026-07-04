# Kerberoasting Attack — AD Lab Report

**Lab:** salkaev.local (Windows Server AD Domain Controller + Windows 10 client)
**Target account:** `svc_sql` (service account)
**Tools used:** Active Directory Users and Computers, `setspn`, Rubeus 1.6.4, Hashcat 7.1.2 (mode 19700, rockyou.txt wordlist)

## Objective

Simulate a Kerberoasting attack against a service account in my home AD lab, extract and crack the resulting TGS hash, and use the results to build a Splunk detection rule for this technique as part of my AD-Splunk-Lab project.

## Background

Kerberoasting targets service accounts that have a Service Principal Name (SPN) registered in Active Directory. Any authenticated domain user can request a Kerberos service ticket (TGS) for such an account without needing elevated privileges. The ticket is encrypted with the service account's password hash, which means it can be extracted and cracked offline — no interaction with the target service is required after the ticket is obtained.

## Step 1 — Identify a Kerberoastable Account

Before attacking anything, I confirmed which account in the domain actually had an SPN registered, since only SPN-bound accounts are exploitable this way.

In Active Directory Users and Computers, the `svc_sql` account's Attribute Editor shows a `servicePrincipalName` value of `http/svc_sql.salkaev.local`:

![SPN attribute on svc_sql](images/01_spn_attribute.png)

I confirmed the same thing from the command line with `setspn -L`, run from both an English-locale host and my Russian-locale VM, to make sure the SPN registration was consistent and correctly readable from a standard admin session:

![setspn -L output, English locale](images/02_setspn_query_en.png)

![setspn -L output, Russian locale VM](images/03_setspn_query_ru.png)

**Why this matters:** in a real environment, this reconnaissance step would normally be done with a tool like PowerView or a plain LDAP query filtering on `servicePrincipalName=*`, since an attacker doesn't have GUI access to ADUC. I used ADUC here only because it's my own lab and I wanted to visually verify the attribute before automating anything.

## Step 2 — Request and Extract the TGS Hash

I used [Rubeus](https://github.com/GhostPack/Rubeus) (v1.6.4), a well-known open-source Kerberos abuse toolkit, to request a service ticket for `svc_sql` and extract it in a crackable format:

![Rubeus GitHub repository](images/04_rubeus_tool.png)

```
Rubeus.exe kerberoast /domain:salkaev.local /dc:192.168.10.7
```

Rubeus enumerated the domain over LDAP, found one Kerberoastable account (`svc_sql`), and returned its TGS hash directly:

![Rubeus kerberoasting output](images/05_rubeus_kerberoast.png)

Key details from the output:
- **SamAccountName:** svc_sql
- **ServicePrincipalName:** http/svc_sql.salkaev.local
- **Supported ETypes:** RC4_HMAC_DEFAULT — meaning the ticket is encrypted with RC4 (etype 23), the weakest and fastest-to-crack Kerberos encryption type still commonly seen in real environments due to legacy application compatibility.

## Step 3 — Crack the Hash Offline

The extracted hash (`$krb5tgs$18$svc_sql...`) was fed into Hashcat using mode `19700` (Kerberos 5, etype 18, TGS-REP) against the `rockyou.txt` wordlist:

```
hashcat.exe -m 19700 hash_clean.txt rockyou.txt
```

The password was cracked successfully:

![Hashcat cracked result](images/06_hashcat_cracked.png)

Hashcat reported a `Cracked` status, confirming that the `svc_sql` account's password was weak enough to be recovered from a standard wordlist without any masks or rules applied.

## What Didn't Work (Troubleshooting Notes)

The path from "Rubeus writes a hash file" to "Hashcat actually loads it" was not as smooth as the final result suggests, and this part is worth documenting because the failure mode is a real, recurring gotcha:

- The first hash file Rubeus wrote (via `/outfile:`) looked correct in the console, but Hashcat rejected it with `Separator unmatched` / `Token length exception`. The root cause was a **UTF-8 Byte Order Mark (BOM)** silently prepended to the file — Rubeus/.NET writes files with a BOM by default, and Hashcat's parser treats those extra invisible bytes as part of the hash structure, so it can't match the format.
- Manually retyping or copy-pasting the hash through the PowerShell console made things worse, not better — long lines got wrapped and split by the terminal, and at least one asterisk delimiter was lost in the process, which produced a different error (`Separator unmatched` for a different reason: a missing field, not a BOM).
- The fix was to stop editing the file by hand entirely and instead extract only the hash line and re-save it explicitly without a BOM (`-Encoding ascii` / `utf8NoBOM`, verified with `Format-Hex`), rather than trusting the raw Rubeus output file or manual retyping.

**Takeaway:** when a hash "looks right" in the terminal but a cracking tool refuses to parse it, check the file's raw bytes before assuming the hash itself is wrong.

## Result

- Successfully identified a Kerberoastable service account in the lab domain.
- Extracted its TGS hash without triggering any interaction with the service itself.
- Cracked the account's password offline using a standard wordlist, with no rate-limiting or lockout risk, since Kerberoasting doesn't touch the authentication path that account lockout policies monitor.

## Detection Recommendations (for AD-Splunk-Lab)

Based on this attack, the following should be detectable in Splunk via Windows Security Event ID **4769** (Kerberos Service Ticket Request):

1. **Encryption type filter** — flag 4769 events where `Ticket_Encryption_Type` is `0x17` (RC4), since modern, properly configured environments should predominantly use AES (`0x11`/`0x12`). A sudden RC4 request for an account that normally uses AES is a strong signal.
2. **Frequency/volume anomaly** — a single source account requesting TGS tickets for multiple different SPNs in a short time window is consistent with a Kerberoasting sweep (as opposed to normal application behavior, which requests a ticket for *one* known service repeatedly).
3. **Noise filtering** — exclude machine accounts (`$`-suffixed accounts), which generate the majority of baseline Kerberos traffic, before applying either rule above. Without this filter, both detections above will be dominated by legitimate computer-account noise.

Next step: implement rule #1 as a working SPL query against the lab's Splunk index and validate it fires on this exact attack replay.

## Environment Notes

- Domain: `salkaev.local`
- Domain Controller: `192.168.10.7`
- Attack host: Windows 10 client (VirtualBox VM)
- All activity performed against my own isolated home lab; no external systems or accounts were involved.
