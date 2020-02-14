UCX_INSTALL_DIR=$$(pwd)/../install-debug/
export LD_LIBRARY_PATH=${UCX_INSTALL_DIR}/lib/:$LD_LIBRARY_PATH
all:ucp_server.c ucp_client.c ucp_tag_server.c ucp_tag_client.c ucp_tag_server_write.c ucp_tag_client_write.c
	gcc -Wall -o server ucp_server.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs -lpthread
	gcc -Wall -o client ucp_client.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o tag_server_read ucp_tag_server.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs -lpthread
	gcc -Wall -o tag_client_read ucp_tag_client.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o tag_server_write ucp_tag_server_write.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
	gcc -Wall -o tag_client_write ucp_tag_client_write.c -I ${UCX_INSTALL_DIR}/include/ -L ${UCX_INSTALL_DIR}/lib/ -lucp -luct -lucs
clean::
	rm -f $$(pwd)/server $$(pwd)/client $$(pwd)/tag_server_read $$(pwd)/tag_client_read $$(pwd)/tag_server_write $$(pwd)/tag_client_write
