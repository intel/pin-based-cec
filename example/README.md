Pin-based Constant Execution Checker (Pin-based CEC) Usage Example
==================================================================

This example demonstrates how to use Pin-based CEC to check for secret-dependent execution in a naive implementation of AES key expansion that uses a lookup-table-based Sbox. The key expansion is implemented as three functions in [`test.c`](test.c): `aes128_key_expansion()`, which fills out the Rijndael key schedule, `rot_word()`, which left-rotates a dword by 8 bits, and `sub_word()`, which replaces the bytes of a dword with the results of an Sbox transformation. Because `sub_word()` uses the secret-dependent input as an index into a lookup table in memory to compute the Sbox transformation, the input into the Sbox operation may be recovered via a cache-based side channel attack. This is a side channel vulnerability that can leak an AES key.

Dependencies
------------

- Linux
- python 3.5 or greater
- gcc/g++/make
- diff

Building and Running
--------------------

1. Build the Pin-based CEC by following instructions in the [main README](../README.md).

2. Move to the `example` directory and build the example program:

```bash
cd example
make
```

The example program does AES key expansion 10 times with random keys. Typically, the subroutine of interest should be exercised with a sufficient number of unique inputs to ensure a high confidence in the results. The Pin-based CEC test could be performed in conjunction with a code-coverage tool to ensure that all relevant sections of the code have been exercised sufficiently.

3. Run the example program and observe that it works as expected:

```bash
./keyexp-test
```

4. Run the example program through Pin-based CEC:

```bash
make run PIN_ROOT=<Pin top-level path>
```

This command executes the `keyexp-test` program and instructs Pin-based CEC to instrument and track the `aes128_key_expansion()` function.

5. Post-process the logs to identify any secret-dependent differences:

```bash
python ../post_process.py results.txt
```

This script applies the taint information to the execution traces and diffs them to check for secret-dependent non-constant execution or memory accesses.

6. The script should output some text on stdout and in `results.txt` that looks like the following (but with more lines):

```text
    Addresses with tainted memory access differences:
        55B0A4453214 --> sub_word (keyexp-test @ 1214)
        55B0A4453228 --> sub_word (keyexp-test @ 1228)
        55B0A445323C --> sub_word (keyexp-test @ 123C)
        55B0A4453250 --> sub_word (keyexp-test @ 1250)
```

These are the addresses that had execution differences and were also identified as operating on secret data by the taint analysis. On the left of the arrow is the address, and on the right is the symbol name in the binary that contains that address (or "???" if no corresponding symbol could be found), the image name, and the offset within that image where the instruction is. In this case, 4 instructions in the `sub_word()` function are flagged. These are the 4 instructions that perform lookups into the Sbox table in memory. We can quickly verify that is the case by looking at the annotated disassembly of `sub_word()`:

```text
uint8_t s0 = AES_SBOX[b0];
    1207:       0f b6 45 f8             movzx  eax,BYTE PTR [rbp-0x8]
    120b:       48 98                   cdqe
    120d:       48 8d 15 ac 2e 00 00    lea    rdx,[rip+0x2eac]         # 40c0 <AES_SBOX>
    1214:       0f b6 04 10             movzx  eax,BYTE PTR [rax+rdx*1] # Secret dependent memory access here!
    1218:       88 45 fc                mov    BYTE PTR [rbp-0x4],al
uint8_t s1 = AES_SBOX[b1];
    121b:       0f b6 45 f9             movzx  eax,BYTE PTR [rbp-0x7]
    121f:       48 98                   cdqe
    1221:       48 8d 15 98 2e 00 00    lea    rdx,[rip+0x2e98]         # 40c0 <AES_SBOX>
    1228:       0f b6 04 10             movzx  eax,BYTE PTR [rax+rdx*1] # Secret dependent memory access here!
    122c:       88 45 fd                mov    BYTE PTR [rbp-0x3],al
uint8_t s2 = AES_SBOX[b2];
    122f:       0f b6 45 fa             movzx  eax,BYTE PTR [rbp-0x6]
    1233:       48 98                   cdqe
    1235:       48 8d 15 84 2e 00 00    lea    rdx,[rip+0x2e84]         # 40c0 <AES_SBOX>
    123c:       0f b6 04 10             movzx  eax,BYTE PTR [rax+rdx*1] # Secret dependent memory access here!
    1240:       88 45 fe                mov    BYTE PTR [rbp-0x2],al
uint8_t s3 = AES_SBOX[b3];
    1243:       0f b6 45 fb             movzx  eax,BYTE PTR [rbp-0x5]
    1247:       48 98                   cdqe
    1249:       48 8d 15 70 2e 00 00    lea    rdx,[rip+0x2e70]         # 40c0 <AES_SBOX>
    1250:       0f b6 04 10             movzx  eax,BYTE PTR [rax+rdx*1] # Secret dependent memory access here!
    1254:       88 45 ff                mov    BYTE PTR [rbp-0x1],al
```
