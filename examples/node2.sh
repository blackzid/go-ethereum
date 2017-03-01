../build/bin/geth \
\
--networkid 52234 \
--port 30304 \
--rpcport 8546 \
--datadir "bdata/node2" \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--num_validators 4 \
--node_num 1
