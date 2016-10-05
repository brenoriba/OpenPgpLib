# OpenPgpLib

> Open PGP Lib for C# .NET based on Bouncy Castle
[http://www.bouncycastle.org/index.html]

# To encrypt a file

```csharp
   OpenPgp.EncryptFile ("YOUR INPUT FILE NAME", "OUTPUT FILE NAME", "YOUR PUBLIC KEY FILE NAME", false, false);
```

# To decrypt a file

```csharp
OpenPgp.DecryptFile ("YOUR INPUT FILE NAME", "OUTPUT FILE NAME", "YOUR PRIVATE KEY FILE NAME", "PRIVATE KEY PASSPHRASE");
```

> Keys generated on PGP Key Generator
[https://pgpkeygen.com/]
