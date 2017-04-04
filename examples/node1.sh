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
--bft \
--verbosity 5 \
--allow-empty \
--num-validators 4 \
--node-num 0
