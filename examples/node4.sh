../build/bin/geth \
\
--networkid 52234 \
--port 30306 \
--rpcport 8548 \
--datadir "bdata/node4" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--num_validators 4 \
--node_num 3
