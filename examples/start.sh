nohup ./node1.sh 2>>bdata/logs/n1.log &
sleep 0.5;
nohup ./node2.sh 2>>bdata/logs/n2.log &
sleep 0.5;
nohup ./node3.sh 2>>bdata/logs/n3.log &
sleep 0.5;
nohup ./node4.sh 2>>bdata/logs/n4.log &
