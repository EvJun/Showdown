# SHOWDOWN - Remediation Guide

This document covers how to remediate potential harm caused by tools run during
an internal penetration test. It is intended for the client's IT/security team.

---

## 1. LLMNR / NBT-NS Poisoning (Responder)

### What happened

Responder listens on the local network segment and replies to Windows broadcast
name-resolution queries (LLMNR and NBT-NS). When a Windows host fails to resolve
a hostname via DNS, it falls back to these protocols and broadcasts a query.
Responder answers those broadcasts with a forged response, causing the Windows
host to send an NTLMv2 authentication attempt to the tester's machine.

This affects every host on the same LAN segment as the tester's machine, not
only the declared scope targets.

### Immediate steps

1. Stop Responder if still running: `pkill responder`
2. Identify which hosts authenticated to the tester's machine:
   - Review `/usr/share/responder/logs/` on the tester's machine for captured hashes
   - Each entry shows the source IP, username, and hash
3. Assume any captured NTLMv2 hash is compromised - treat as a credential exposure
4. Notify affected users to change their passwords before the hashes can be cracked

### Disable LLMNR (Group Policy)

`Computer Configuration > Administrative Templates > Network > DNS Client`
- Set **Turn off multicast name resolution** to **Enabled**

Or via registry (deploy via GPO or script):
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
EnableMulticast = 0 (DWORD)
```

### Disable NBT-NS

Per adapter via PowerShell (run on each host, or deploy via GPO startup script):
```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
```

### Verify remediation

After pushing the GPO, confirm LLMNR is disabled from a test host:
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast
```
Value should be `0`.

---

## 2. Captured NTLMv2 Hashes

### What happened

NTLMv2 hashes captured by Responder can be cracked offline using hashcat.
Cracking does not interact with the target network - it is done entirely locally
by the tester. If a hash is cracked, the plaintext password is recovered.

### Steps

1. **Force password reset** for every user whose hash was captured, regardless
   of whether cracking succeeded. A hash can be cracked after the engagement ends.
2. Review Active Directory sign-in logs for the affected users:
   - Azure AD: Entra ID > Sign-in logs > filter by username
   - On-prem AD: Event ID 4624 (successful logon), 4625 (failed logon) on DCs
3. If any cracked credentials were used in downstream attacks (Pass-the-Hash,
   lateral movement), review those hosts for unauthorised access

---

## 3. Pass-the-Hash / Remote Execution

### What happened

If valid NTLM hashes or plaintext credentials were obtained, they may have been
used to authenticate to other hosts via SMB (psexec, wmiexec, CrackMapExec)
without cracking the password.

### Steps

1. Check which hosts were accessed - review the session's `lateral/` output files
2. On accessed hosts, review:
   - Windows Event Log: Event ID 4624 (logon), 4648 (explicit credential logon)
   - Security log for Service Control Manager events (psexec creates a service)
3. Force password reset for any account used in lateral movement
4. Enable **SMB signing** to prevent NTLM relay attacks:

```
Computer Configuration > Windows Settings > Security Settings >
  Local Policies > Security Options
  - Microsoft network server: Digitally sign communications (always) = Enabled
  - Microsoft network client: Digitally sign communications (always) = Enabled
```

Or via PowerShell:
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

---

## 4. Kerberoasting

### What happened

Any authenticated domain user can request a Kerberos service ticket (TGS) for
any Service Principal Name (SPN). The ticket is encrypted with the service
account's password hash and can be cracked offline. No lockout occurs.

### Steps

1. Identify which SPNs were requested - review the session's `lateral/kerberoast_hashes.txt`
2. **Rotate the password** for every service account whose SPN was targeted
   - Use a long, random password (25+ characters) - Kerberoasting only succeeds
     against weak passwords
3. Consider enabling **Protected Users** security group for sensitive service accounts
4. Audit all SPNs registered in the domain - remove stale ones:
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
    Select-Object Name, ServicePrincipalName
```

---

## 5. Long-term Hardening Recommendations

| Control | Why it helps |
|---|---|
| Disable LLMNR and NBT-NS (see above) | Eliminates the attack surface Responder relies on |
| Enforce SMB signing | Prevents NTLM relay even if hashes are captured |
| Enable Extended Protection for Authentication (EPA) | Blocks cross-protocol relay attacks |
| Tiered admin model (separate accounts per tier) | Limits blast radius of any single credential compromise |
| LAPS (Local Administrator Password Solution) | Unique local admin passwords per host - breaks lateral movement |
| Credential Guard | Protects NTLM hashes in memory from tools like Mimikatz |
| Audit Kerberos service ticket requests (Event 4769) | Detect Kerberoasting attempts in real time |

---

## References

- Microsoft: Disable LLMNR - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-netbios-tcp-ip-using-dhcp
- Microsoft: SMB signing - https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3
- Microsoft: LAPS - https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- Microsoft: Credential Guard - https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard
- MITRE ATT&CK T1557.001 (LLMNR Poisoning) - https://attack.mitre.org/techniques/T1557/001/
- MITRE ATT&CK T1558.003 (Kerberoasting) - https://attack.mitre.org/techniques/T1558/003/
