./go-ethereum/build/bin/geth \
\
--networkid 2234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug,admin,miner" \
\
--bft \
--allow-empty \
--num-validators 2 \
--node-num 0
