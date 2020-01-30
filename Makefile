WORK_DIR=$$(pwd)
export LD_LIBRARY_PATH=${WORK_DIR}/../install-debug/lib/:$LD_LIBRARY_PATH
all:ucp_server.c ucp_client.c
	gcc -Wall -o server ucp_server.c -I ${WORK_DIR}/../install-debug/include/ -L ${WORK_DIR}/../install-debug/lib/ -lucp -luct -lucs
	gcc -Wall -o client ucp_client.c -I ${WORK_DIR}/../install-debug/include/ -L ${WORK_DIR}/../install-debug/lib/ -lucp -luct -lucs
clean::
	rm -f ${WORK_DIR}/server ${WORK_DIR}/client
