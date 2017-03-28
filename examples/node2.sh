../build/bin/geth \
\
--networkid 52234 \
--port 30304 \
--rpcport 8546 \
--datadir "bdata/node2" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--verbosity 5 \
--bft \
--num-validators 4 \
--node-num 1
