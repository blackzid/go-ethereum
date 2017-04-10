../build/bin/geth \
\
--networkid 52234 \
--port 30308 \
--rpcport 8550 \
--datadir "bdata/node6" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--bft \
--allow-empty \
--num-validators 8 \
--node-num 5
