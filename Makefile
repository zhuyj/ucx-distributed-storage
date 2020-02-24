UCX_INSTALL_DIR=$$(pwd)/../install-debug/
INCLUDE_DIR=${UCX_INSTALL_DIR}/include/
LIB_DIR=${UCX_INSTALL_DIR}/lib/
FLAGS=-lucp -luct -lucs -Wall
EXTRA_FLAGS=-lpthread
DEBUG_FLAGS=-g
export LD_LIBRARY_PATH=${UCX_INSTALL_DIR}/lib/:$LD_LIBRARY_PATH
all:ucp_server.c ucp_client.c ucp_tag_server.c ucp_tag_client.c ucp_tag_server_write.c ucp_tag_client_write.c
	gcc -o server ucp_server.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS} ${EXTRA_FLAGS}
	gcc -o client ucp_client.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS}
	gcc -o tag_server_read ucp_tag_server.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS} ${EXTRA_FLAGS}
	gcc -o tag_client_read ucp_tag_client.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS}
	gcc -o tag_server_write ucp_tag_server_write.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS}
	gcc -o tag_client_write ucp_tag_client_write.c -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS}
clean::
	rm -f $$(pwd)/server $$(pwd)/client $$(pwd)/tag_server_read $$(pwd)/tag_client_read $$(pwd)/tag_server_write $$(pwd)/tag_client_write
