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
The verb **p** prints the file one line at a time, as required by the factotum control file.
Files are extracted with mode 600.
(The interface is different from the Plan 9 *auth/secstore* command, being closer to Inferno's version.)
The service allows only simple file names. If a path is given, secfiles uses the base name as the file name on secstore.
The **-s** option gives the server name and port (default port: 5356).
Given the **-i** option, secfiles reads up to two lines from standard input: the user's key and an optional PIN.
The secstore user name defaults to the current user name.
The server can also be given by the **SECSTORE** environment variable.
The key can be given by the **SECSTOREKEY** environment variable.

The test for package secstore uses three environment variables:

	TESTSERVER the server name and port
	TESTUSER the user name on the secstore service
	TESTKEY the key for $TESTUSER

The test reads and decrypts any files stored by $TESTUSER,
and re-encrypts them locally to test encryption.
It also writes a short verse to the file **mary** on the service.
