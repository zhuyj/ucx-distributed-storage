UCX_INSTALL_DIR=$$(pwd)/../install-debug/
export LD_LIBRARY_PATH=${UCX_INSTALL_DIR}/lib/:$LD_LIBRARY_PATH
all:ucp_server.c ucp_client.c
	gcc -Wall -o server ucp_server.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o client ucp_client.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o tag_server ucp_tag_server.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o tag_client ucp_tag_client.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
clean::
	rm -f $$(pwd)/server $$(pwd)/client $$(pwd)/tag_server $$(pwd)/tag_client
