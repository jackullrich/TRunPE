# TRunPE
A modified RunPE (process hollowing) technique which avoids SetThreadContext by appending a TLS section which calls the original entrypoint.

https://winternl.com/trunpe

Tested with McAfee's bintext.exe on Windows 10.
