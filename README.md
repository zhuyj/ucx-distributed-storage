# ucx-distributed-storage
The steps to compile and run this ucx distributed storage app:

1. git clone https://github.com/openucx/ucx.git ucx

2. cd ucx && ./autogen.sh && ./contrib/configure-devel --prefix=$PWD/install-debug && make && make install

3. ls $PWD/install-debug
   "
     bin  include  lib  share
   "

4. To now, the ucx is ready. We can complile ucx distributed storage app;
