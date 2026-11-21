# Render library: review

Written by `mirage-profile render-library`. Every answer below is what a real Debian 12
host printed; nothing was typed in. Read each one as an attacker would: is there anything
in it that the decoy's story does not support?

Reference image: `sha256:655d2a9ebce417af6a8aef6e9f5655755153a9e8b7d2839a860995cfcaa82bf8`, Debian 12.15, amd64.

## any hardware class

### `nginx -v`

- From: reference-container; program `/usr/sbin/nginx`; answers any user.
- Exit code 0; output on stderr; shape error; measured 3, 3, 3, 3, 3 ms.
- Inventory count: corpus 0, lab 5. Slots: none.

stderr:

```
nginx version: nginx/1.22.1
```

### `nginx -t`

- From: reference-container; program `/usr/sbin/nginx`; answers root only.
- Exit code 0; output on stderr; shape error; measured 4, 4, 4, 4, 4 ms.
- Inventory count: corpus 0, lab 4. Slots: none.

stderr:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### `sshd -t`

- From: reference-container; program `/usr/sbin/sshd`; answers root only.
- Exit code 0; output on neither; shape empty; measured 9, 9, 8, 8, 7 ms.
- Inventory count: corpus 0, lab 1. Slots: none.

### `locale -a`

- From: reference-container; program `/usr/bin/locale`; answers any user.
- Exit code 0; output on stdout; shape text; measured 2, 2, 2, 1, 2 ms.
- Inventory count: responder 1. Slots: none.

stdout:

```
C
C.utf8
POSIX
```

### `nginx -h`

- From: reference-container; program `/usr/sbin/nginx`; answers any user.
- Exit code 0; output on stderr; shape error; measured 3, 3, 3, 3, 3 ms.
- Inventory count: responder 1. Slots: none.

stderr:

```
nginx version: nginx/1.22.1
Usage: nginx [-?hvVtTq] [-s signal] [-p prefix]
             [-e filename] [-c filename] [-g directives]

Options:
  -?,-h         : this help
  -v            : show version and exit
  -V            : show version and configure options then exit
  -t            : test configuration and exit
  -T            : test configuration, dump it and exit
  -q            : suppress non-error messages during configuration testing
  -s signal     : send signal to a master process: stop, quit, reopen, reload
  -p prefix     : set prefix path (default: /usr/share/nginx/)
  -e filename   : set error log file (default: stderr)
  -c filename   : set configuration file (default: /etc/nginx/nginx.conf)
  -g directives : set global directives out of configuration file
```

### `openssl version`

- From: reference-container; program `/usr/bin/openssl`; answers any user.
- Exit code 0; output on stdout; shape text; measured 22, 3, 3, 3, 3 ms.
- Inventory count: responder 1. Slots: none.

stdout:

```
OpenSSL 3.0.22 25 Aug 2026 (Library: OpenSSL 3.0.22 25 Aug 2026)
```

### `sysctl kernel.ostype`

- From: reference-container; program `/usr/sbin/sysctl`; answers any user.
- Exit code 0; output on stdout; shape text; measured 10, 2, 2, 2, 2 ms.
- Inventory count: responder 1. Slots: none.

stdout:

```
kernel.ostype = Linux
```

### `sysctl vm.swappiness`

- From: reference-container; program `/usr/sbin/sysctl`; answers any user.
- Exit code 0; output on stdout; shape text; measured 2, 2, 2, 2, 2 ms.
- Inventory count: responder 1. Slots: none.

stdout:

```
vm.swappiness = 60
```

## class `kvm-epyc-1c-2g`

### `lscpu`

- From: class-record; program `/usr/bin/lscpu`; answers any user.
- Exit code 0; output on stdout; shape keyvalue; measured 3 ms.
- Inventory count: corpus 7, lab 0. Slots: none.

stdout:

```
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           40 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  1
On-line CPU(s) list:                     0
Vendor ID:                               AuthenticAMD
BIOS Vendor ID:                          QEMU
Model name:                              AMD EPYC Processor
BIOS Model name:                         pc-i440fx-7.2  CPU @ 2.0GHz
BIOS CPU family:                         1
CPU family:                              23
Model:                                   1
Thread(s) per core:                      1
Core(s) per socket:                      1
Socket(s):                               1
Stepping:                                2
BogoMIPS:                                6986.86
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 arat
Hypervisor vendor:                       KVM
Virtualization type:                     full
L1d cache:                               32 KiB (1 instance)
L1i cache:                               64 KiB (1 instance)
L2 cache:                                512 KiB (1 instance)
L3 cache:                                8 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0
Vulnerability Gather data sampling:      Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Reg file data sampling:    Not affected
Vulnerability Retbleed:                  Mitigation; untrained return thunk; SMT disabled
Vulnerability Spec rstack overflow:      Mitigation; safe RET, no microcode
Vulnerability Spec store bypass:         Vulnerable
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Retpolines; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Not affected
```

### `nproc`

- From: class-record; program `/usr/bin/nproc`; answers any user.
- Exit code 0; output on stdout; shape text; measured 1 ms.
- Inventory count: corpus 6, lab 1. Slots: none.

stdout:

```
1
```

### `df -h`

- From: class-record; program `/usr/bin/df`; answers any user.
- Exit code 0; output on stdout; shape table; measured 1 ms.
- Inventory count: corpus 5, lab 0. Slots: none.

stdout:

```
Filesystem      Size  Used Avail Use% Mounted on
udev            965M     0  965M   0% /dev
tmpfs           197M  436K  197M   1% /run
/dev/vda1        40G 1002M   37G   3% /
tmpfs           984M     0  984M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/vda15      124M   12M  112M  10% /boot/efi
```

## class `kvm-epyc-2c-4g`

### `lscpu`

- From: class-record; program `/usr/bin/lscpu`; answers any user.
- Exit code 0; output on stdout; shape keyvalue; measured 3 ms.
- Inventory count: corpus 7, lab 0. Slots: none.

stdout:

```
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           40 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  2
On-line CPU(s) list:                     0,1
Vendor ID:                               AuthenticAMD
BIOS Vendor ID:                          QEMU
Model name:                              AMD EPYC-Rome Processor
BIOS Model name:                         pc-i440fx-7.2  CPU @ 2.0GHz
BIOS CPU family:                         1
CPU family:                              23
Model:                                   49
Thread(s) per core:                      1
Core(s) per socket:                      2
Socket(s):                               1
Stepping:                                0
BogoMIPS:                                6986.86
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext perfctr_core ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr wbnoinvd arat umip rdpid
Hypervisor vendor:                       KVM
Virtualization type:                     full
L1d cache:                               64 KiB (2 instances)
L1i cache:                               64 KiB (2 instances)
L2 cache:                                1 MiB (2 instances)
L3 cache:                                16 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0,1
Vulnerability Gather data sampling:      Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Reg file data sampling:    Not affected
Vulnerability Retbleed:                  Mitigation; untrained return thunk; SMT disabled
Vulnerability Spec rstack overflow:      Mitigation; SMT disabled
Vulnerability Spec store bypass:         Vulnerable
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Retpolines; IBPB conditional; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Not affected
```

### `nproc`

- From: class-record; program `/usr/bin/nproc`; answers any user.
- Exit code 0; output on stdout; shape text; measured 1 ms.
- Inventory count: corpus 6, lab 1. Slots: none.

stdout:

```
2
```

### `df -h`

- From: class-record; program `/usr/bin/df`; answers any user.
- Exit code 0; output on stdout; shape table; measured 1 ms.
- Inventory count: corpus 5, lab 0. Slots: none.

stdout:

```
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           392M  440K  392M   1% /run
/dev/vda1        79G 1002M   75G   2% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/vda15      124M   12M  112M  10% /boot/efi
```

## class `kvm-epyc-4c-8g`

### `lscpu`

- From: class-record; program `/usr/bin/lscpu`; answers any user.
- Exit code 0; output on stdout; shape keyvalue; measured 11 ms.
- Inventory count: corpus 7, lab 0. Slots: none.

stdout:

```
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           40 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  4
On-line CPU(s) list:                     0-3
Vendor ID:                               AuthenticAMD
BIOS Vendor ID:                          QEMU
Model name:                              AMD EPYC-Milan Processor
BIOS Model name:                         pc-q35-7.2  CPU @ 2.0GHz
BIOS CPU family:                         1
CPU family:                              25
Model:                                   1
Thread(s) per core:                      1
Core(s) per socket:                      4
Socket(s):                               1
Stepping:                                1
BogoMIPS:                                6986.86
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext perfctr_core ssbd ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves clzero xsaveerptr wbnoinvd arat umip pku ospke rdpid fsrm
Hypervisor vendor:                       KVM
Virtualization type:                     full
L1d cache:                               128 KiB (4 instances)
L1i cache:                               128 KiB (4 instances)
L2 cache:                                2 MiB (4 instances)
L3 cache:                                32 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0-3
Vulnerability Gather data sampling:      Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Reg file data sampling:    Not affected
Vulnerability Retbleed:                  Not affected
Vulnerability Spec rstack overflow:      Mitigation; safe RET
Vulnerability Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Retpolines; IBPB conditional; IBRS_FW; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Vulnerable: Clear CPU buffers attempted, no microcode
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Not affected
```

### `nproc`

- From: class-record; program `/usr/bin/nproc`; answers any user.
- Exit code 0; output on stdout; shape text; measured 7 ms.
- Inventory count: corpus 6, lab 1. Slots: none.

stdout:

```
4
```

### `df -h`

- From: class-record; program `/usr/bin/df`; answers any user.
- Exit code 0; output on stdout; shape table; measured 1 ms.
- Inventory count: corpus 5, lab 0. Slots: none.

stdout:

```
Filesystem      Size  Used Avail Use% Mounted on
udev            3.9G     0  3.9G   0% /dev
tmpfs           795M  496K  794M   1% /run
/dev/sda1       158G 1002M  150G   1% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda15      124M   12M  112M  10% /boot/efi
```

## Left out

- `lsof -i -nP`: Its answer names process IDs and the caller's own connection, which must agree with `ps` and `ss`. Both now read the deployment's process list and its sockets (fork patches 0016 and 0021), so `lsof` can be emulated from the same two; a fixed text cannot hold it.
