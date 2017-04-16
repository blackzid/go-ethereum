nohup ./node1.sh 2>>bdata/logs/n1.log &
sleep 0.3;
nohup ./node2.sh 2>>bdata/logs/n2.log &
