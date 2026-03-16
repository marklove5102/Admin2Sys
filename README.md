# Admin2Sys
A Windows token-theft utility that enumerates SYSTEM processes, duplicates their access token, and spawns a new process running as NT AUTHORITY\SYSTEM.

# Usage
Let's use and prove it:

First of all i open a Windows 10 Home, with Antivirus (Kaspersky) and Windows Defender activated.

Now i transfer the malicious binary to execute it:

![image](https://user-images.githubusercontent.com/79543461/235515992-f2535ab8-045c-4d78-8d56-12e8a7af0b36.png)

And now i execute it:

![image](https://user-images.githubusercontent.com/79543461/235516023-c61fdf56-fa7d-4862-ad3b-124ccc3e3be0.png)

In this case i execute a CMD.

![image](https://user-images.githubusercontent.com/79543461/235516085-01538fd4-1875-4764-83da-c9dd0d468496.png)

And this is a popped CMD, now i execute the whoami command:

![image](https://user-images.githubusercontent.com/79543461/235516137-a3dcdc6a-da3d-4b86-9a84-a8a35202a8e5.png)

# Code
**1. Enable debug privileges**
The program first enables SeDebugPrivilege so it can open handles to protected SYSTEM processes.

**2. Enumerate running processes**
It creates a snapshot using:

- CreateToolhelp32Snapshot
- Process32First
- Process32Next

to iterate through all running processes.

**3. Target known SYSTEM processes**
It filters processes such as:

- winlogon.exe
- services.exe
- svchost.exe
- lsass.exe

which normally run as SYSTEM.

**4. Steal the process token**
For each candidate process:

- OpenProcess() obtains a handle

- OpenProcessToken() retrieves its security token

**5. Verify the token belongs to SYSTEM**
The token is checked with GetTokenInformation(TokenUser) and compared against the SYSTEM SID (S-1-5-18) using EqualSid.

**6. Duplicate the token**
If the token is valid:

- DuplicateTokenEx() converts it into a primary token that can create new processes.

**7. Spawn a SYSTEM process**
Finally:

- CreateProcessWithTokenW() launches the user-specified program (e.g., cmd.exe) using the duplicated SYSTEM token.

The result is a new process running with SYSTEM privileges.
