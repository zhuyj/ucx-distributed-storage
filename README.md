# ucx-distributed-storage
The steps to compile and run this ucx distributed storage app:

1. git clone https://github.com/openucx/ucx.git ucx

2. cd ucx && ./autogen.sh && ./contrib/configure-devel --prefix=$PWD/install-debug && make && make install

3. ls $PWD/install-debug
   "
     bin  include  lib  share
   "

4. To now, the ucx is ready. We can complile ucx distributed storage app;

5. git clone this-github-app

6. make UCX_INSTALL_DIR=/ucx-install-debug/

7. run this ucx distributed storage app:

   Server <--------> Client1
   ^   ^^
   |   ||----------> Client2
   |   |-----------> ClientN
   |---------------> Clinet100

   The Server and Clients work very well.

The stream_send/stream_receive client/server APPs:

ucp_server.c
ucp_client.c

Tag_send/tag_recv IO read APPs are ready.

    Client                                         Server

    Send iorequest(ip + request data len) ---->    Receive ip and request data len

    Receive request data                  <----    send the request data

    Receive ioresponse                    <----    send the ioresponse

ucp_tag_server.c
ucp_tag_client.c

Tag_send/tag_recv IO write APPs are ready.

    Client                         Server

    Send IOrequest      -------->  Receive IOrequest

    Send Data           -------->  Receive Data

    Receive IOresponse  <--------  Send IOresponse

ucp_tag_server_write.c
ucp_tag_client_write.c
