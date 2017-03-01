../build/bin/geth \
\
--networkid 52234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node1" \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--num_validators 4 \
--node_num 0
