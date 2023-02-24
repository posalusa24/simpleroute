all:
	@gcc ring.c -o simpleroute -lexplain
	@sudo setcap cap_net_admin,cap_net_raw=eip simpleroute
	@./simpleroute 8.8.8.8
