../build/bin/geth \
\
--networkid 52234 \
--port 30307 \
--rpcport 8549 \
--datadir "bdata/node5" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--allow-empty \
--num-validators 8 \
--node-num 4
