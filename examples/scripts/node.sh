./go-ethereum/build/bin/geth \
\
--networkid 52234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug,admin" \
\
--bft \
--allow-empty \
--num-validators 16 \
--node-num 7
