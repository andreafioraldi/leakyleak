# leakyleak
a POC for the libc address leak using __libc_csu_init from the paper https://www.blackhat.com/docs/asia-18/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf

## Usage
```
python leakyleak.py <binary> [address_of_pointer_to_leak]
```
By default without specifying `address_of_pointer_to_leak` the tool will leak the address of the function used to print the leak (puts, printf or write).


