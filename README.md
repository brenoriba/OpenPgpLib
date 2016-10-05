# OpenPgpLib

Open PGP Lib for C# .NET

Based on Bouncy Castle

http://www.bouncycastle.org/index.html

# To encrypt a file

OpenPgp.EncryptFile ("YOUR INPUT FILE NAME", "OUTPUT FILE NAME", "YOUR PUBLIC KEY FILE NAME", false, false);

# To decrypt a file

OpenPgp.DecryptFile ("YOUR INPUT FILE NAME", "OUTPUT FILE NAME", "YOUR PRIVATE KEY FILE NAME", "PRIVATE KEY PASSPHRASE");
