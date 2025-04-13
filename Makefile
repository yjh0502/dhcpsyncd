dhcpsyncd: dhcpsyncd.c
	cc -O2 -Wall -Wextra -Werror dhcpsyncd.c -o dhcpsyncd

clean:
	rm -f dhcpsyncd
