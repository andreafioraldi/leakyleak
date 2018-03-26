all:
	gcc -O0 -fno-stack-protector vuln_puts.c -o vuln_puts
	gcc -O0 -fno-stack-protector vuln_printf.c -o vuln_printf
	gcc -O0 -fno-stack-protector vuln_write.c -o vuln_write

clean:
	rm vuln_puts vuln_printf vuln_write
