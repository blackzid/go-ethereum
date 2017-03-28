../build/bin/geth \
\
--networkid 52234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node1" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--verbosity 5 \
--bft \
--num-validators 4 \
--node-num 0
