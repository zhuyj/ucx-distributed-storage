UCX_INSTALL_DIR=$$(pwd)/../install-debug/
INCLUDE_DIR=${UCX_INSTALL_DIR}/include/
LIB_DIR=${UCX_INSTALL_DIR}/lib/
FLAGS=-lucp -luct -lucs -Wall
EXTRA_FLAGS=-lpthread
DEBUG_FLAGS=-g
BUILD_FILES=ucp_stream_server.c \
		ucp_stream_client.c \
		ucp_tag_server_read.c \
		ucp_tag_client_read.c \
		ucp_tag_server_write.c \
		ucp_tag_client_write.c

#export LD_LIBRARY_PATH=${UCX_INSTALL_DIR}/lib/:${LD_LIBRARY_PATH}
all:${BUILD_FILES}
	for SOURCE_ENTRY in ${BUILD_FILES}; do \
		BIN_FILE=$$(echo $${SOURCE_ENTRY}|awk -F "." '{print $$1}'); \
		gcc -o $${BIN_FILE} $${SOURCE_ENTRY} -I ${INCLUDE_DIR} -L ${LIB_DIR} ${FLAGS} ${EXTRA_FLAGS}; \
	done
clean::
	for SOURCE_ENTRY in ${BUILD_FILES}; do \
		BIN_FILE=$$(echo $${SOURCE_ENTRY}|awk -F "." '{print $$1}'); \
		rm -f $$(pwd)/$${BIN_FILE}; \
	done
