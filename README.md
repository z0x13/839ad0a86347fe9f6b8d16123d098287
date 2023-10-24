# Template-based injectors generator (version 0, unstable)
## Installation
1. [install rustup](https://www.rust-lang.org/tools/install)
2. `rustup toolchain add nightly-x86_64-pc-windows-msvc`
3. `rustup component add rust-src --toolchain nightly-x86_64-pc-windows-msvc`
4. `cargo build --release`
5. `target/release/project.exe --help`
## Features
### Obfuscation
- ipv4
- ipv6
- mac address
- base32
- base45
- base58
- base64
- base62
- base85
### Encryption
- xor (one byte key)
- smart xor (key length = shellcode length)
- AES
- chacha20
- RC4
- Rabbit
### Detection
#### Antidebug
##### PEB based
- being debugged field
- heap flags
- nt global flag
##### NT query based
- debug port
- debug object
- debug flags
##### Other
- IsDebuggerPresent()
- debug registers
- check remote debugger present
#### sandbox detect
- sbiedll.dll
- cursor position
- input time
#### virtual machine detect
- cpuid
- time-based (rdtsc)
### Extra features
- self-deletion
- debug privilege
### Injection techniques
- etwp
- make_exec
- create fiber
- create thread
- module stomping
- ntapc
- ntcrt
- syscrt
- wincrt
