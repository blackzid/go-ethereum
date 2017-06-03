../build/bin/geth \
\
--networkid 2234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node1" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,debug" \
\
--bft \
--allow-empty \
--num-validators 1 \
--verbosity 5 \
--node-num 0
