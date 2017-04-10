../build/bin/geth \
\
--networkid 52234 \
--port 30310 \
--rpcport 8552 \
--datadir "bdata/node8" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--allow-empty \
--num-validators 8 \
--node-num 7
