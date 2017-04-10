../build/bin/geth \
\
--networkid 52234 \
--port 30309 \
--rpcport 8551 \
--datadir "bdata/node7" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--allow-empty \
--num-validators 8 \
--node-num 6
