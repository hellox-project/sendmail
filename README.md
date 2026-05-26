# Sendmail - SMTP Email Client for HelloX OS

A TLS-encrypted SMTP email sender for HelloX OS, using wolfSSL for TLS and lwIP for networking.

## Features
- SMTP with STARTTLS (port 25) or direct SSL (port 465)
- MIME multipart/mixed with plain text body + file attachments
- Multiple recipients (To) via comma separation
- CC support
- Base64-encoded attachments (up to 8 files, 512KB each)
- Dot-stuffing compliant with RFC 5321 §4.5.2
- No DNS resolution - uses hardcoded IP

## Usage
```
loadapp c:\sendmail.exe [options]

Options (positional, '.' = use default):
  1 server     SMTP server IP    (default smtp.163.com = 111.124.203.45)
  2 port       TCP port          (default 25)
  3 user       SMTP login        (default 13311286388@163.com)
  4 password   Auth code         (default ASUYp5dLEtFHTPxu)
  5 from       Sender            (default 13311286388@163.com)
  6 to         Recipient(s)      (default garryxin@qq.com)
  7 cc         Cc recipients     (default none)
  8 subject    Email subject     (default "AI News from HelloX OS (TLS)")
  
  After params:
    -b <file>  Read body from file
    <file>..   Attachments (max 8, max 512KB each)
```

## Examples
```
loadapp c:\sendmail.exe
loadapp c:\sendmail.exe . . . . . user@qq.com "" "Hello there"
loadapp c:\sendmail.exe . . . . . a@x.com "" "Subject" -b c:\body.txt c:\f1.bin c:\f2.bin
```

## Test Account
- User: 13311286388@163.com
- Auth key: ASUYp5dLEtFHTPxu
- SMTP server: smtp.163.com (111.124.203.45)

## Building
```
cd ~/hellox/v190/sendmail
./build.sh
```

Requires: clang (with -m32 support), binutils (with i386pe support), 
wolfSSL objects (pre-built in this project), sysbrain objects.

## Project Structure
```
sendmail/
├── build.sh          - Build script
├── link.ld           - Linker script (PE32)
├── README.md
├── src/
│   └── sendmail.c    - Main SMTP email source (contains everything)
└── include/
    └── (HelloX headers - reference sysbrain directory)
```
