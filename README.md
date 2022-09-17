# auth
authentication code, typically Plan 9-related, in Go

## secstore package
github.com/forsyth/auth/secstore is a package for interacting with a Plan 9 secstore service
(see https://plan9.io/magic/man2html/8/secstore).

## secfiles command
The command *secfiles* fetches, stores, updates and removes
files stored in a Plan 9 secstore service.

	Usage: secfiles [-i] [-k key] [-p pin] [-s host[:5356]] [-n net] [-u user] [-v] {drptx}[v] [file ...]

The verbs **d**, **r**, **p**, **t** and **x** are similar to those of *ar*(1) or *tar*(1):

**d** delete  
**r** replace (store or update)  
**p** print to standard output  
**t** table  
**x** extract  

The optional **v** modifier adds detail.
(The interface is different from the Plan 9 *auth/secstore* command, being closer to Inferno's version.)
The **-s** option gives the server name and port (default port: 5356).
Given the **-i** option, secfiles reads up to two lines from standard input: the user's key and an optional PIN.
The secstore user name defaults to the current user name.
The server can also be given by the **SECSTORE** environment variable.
The key can be given by the **SECSTOREKEY** environment variable.

The *secstore* service stores a set of encrypted files. They are encrypted and decrypted only on the client.
The user's key is not stored on the server.
Files are exchanged (in encrypted form) using a special protocol on a separately encrypted connection.
The typical use with Plan 9 is to store a file of keys to be loaded into an instance of *factotum*(4).

The service allows only simple file names.
If a path is given, *secfiles* uses the base name as the file name on *secstore*.
Files are extracted with mode 600.
The verb **p** prints the file one line at a time, as required by the factotum control file.

## Test conventions
The test for package secstore uses three environment variables:

**TESTSERVER** the server name and port  
**TESTUSER** the user name on the secstore service  
**TESTKEY** the key for **$TESTUSER**  

The test reads and decrypts any files stored by **$TESTUSER**,
and re-encrypts them locally to test encryption.
It also writes a short verse to the file **mary** on the service, then removes it.

## Bugs and restrictions
The *secstore* protocol does not handle errors consistently.
It uses an unorthodox version of cipher-block-chaining for AESCBC, retained here for compatibility,
but limited to an internal package so it doesn't escape further.
Because of its age, it uses SHA1 in various ways, but they should be safe in this application.
It also uses the record format of SSL, but nothing else of that protocol.
In particular, the authentication protocol is completely different.
Again, there's an internal version for compatibility.
