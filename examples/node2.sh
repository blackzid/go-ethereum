../build/bin/geth \
\
--networkid 2234 \
--port 30304 \
--rpcport 8546 \
--datadir "bdata/node2" \
--nodiscover \
--mine \
--minerthreads 1 \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,web3,debug" \
\
--verbosity 5 \
--bft \
--allow-empty \
--num-validators 4 \
--node-num 1
