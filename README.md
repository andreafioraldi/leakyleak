# leakyleak
a POC for the libc address leak using __libc_csu_init from the paper https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf

## Usage
```
python leakyleak.py <binary> [address_of_pointer_to_leak] [address_of_libc_csu_init]
```
By default without specifying `address_of_pointer_to_leak` the tool will leak the address of the function used to print the leak (puts, printf or write).

If the binary doesn't export the symbol __libc_csu_init you must specify the parameter `address_of_libc_csu_init`.
