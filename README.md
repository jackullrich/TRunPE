# TRunPE
A modified RunPE (process hollowing) technique avoiding the usage of SetThreadContext by appending a TLS section which calls the original entrypoint.

https://winternl.com/trunpe

Proof-of-Concept Code

# Future Improvements
* Modifying an existing TLS section
* Extending the IMAGE_SECTION_HEADER list if necessary
* Placing the callback code in an already executable section
* Relocation support

Visual Studio 2019

Tested with McAfee's bintext.exe on Windows 10
