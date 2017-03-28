../build/bin/geth \
\
--networkid 52234 \
--port 30305 \
--rpcport 8547 \
--datadir "bdata/node3" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--verbosity 5 \
--bft \
--num-validators 4 \
--node-num 2
