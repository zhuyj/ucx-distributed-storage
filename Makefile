export LD_LIBRARY_PATH=/workspace/yanjunz/install-debug/lib/:$LD_LIBRARY_PATH
all:ucp_server.c ucp_client.c
	gcc -Wall -o server ucp_server.c -I /workspace/yanjunz/install-debug/include/ -L /workspace/yanjunz/install-debug/lib/ -lucp -luct -lucs
	gcc -Wall -o client ucp_client.c -I /workspace/yanjunz/install-debug/include/ -L /workspace/yanjunz/install-debug/lib/ -lucp -luct -lucs
clean::
	rm -f server client
