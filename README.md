# Secure-netcat
Secure netcat

Added security to netcat (linux "nc") using Authenticated Encryption with GCM AES-256.

Usage:

./snc [-l] [--key KEY] [destination] [port]

Example 1:
[client]$ ./snc --key CSC574ISAWESOME server.add.ress 9999 < some-file.txt
[server]$ ./snc --key CSC574ISAWESOME -l 9999 > some-file.txt

Example 2:
[client]$ ./snc --key CSC574ISAWESOME server.add.ress 9999 < file1-in.txt > file2-out.txt
[server]$ ./snc --key CSC574ISAWESOME -l 9999 > file1-out.txt < file2-in.txt

Testing:
Tested on text files upto 1MB.

Testing environment:
OS: Ubuntu 16.04 LTS
python3 version: 3.5.2
