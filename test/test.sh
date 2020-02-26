#!/bin/bash

CLIENT_NUM=128

while [ 1 ]

do

    for i in `seq 1 ${CLIENT_NUM}`

    do

                echo $i

                (./ucp_tag_client_read -a 1.1.1.5&)

        done

        finished=`ps uxww | grep ucp_tag_client_read | grep -v grep`

        while [ X"$finished" != X"" ]

        do

                sleep 1;

                finished=`ps uxww | grep ucp_tag_client_read | grep -v grep`

        done

        sleep 3

        echo "new tests begin..."

done
