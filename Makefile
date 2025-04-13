dhcpsyncd: dhcpsyncd.c
	cc -O2 -Wall -Werror dhcpsyncd.c -o dhcpsyncd

clean:
	rm -f dhcpsyncd
