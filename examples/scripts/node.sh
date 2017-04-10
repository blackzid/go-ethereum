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
--num-validators 8 \
--node-num 0
