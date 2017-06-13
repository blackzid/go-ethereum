../build/bin/geth \
\
--networkid 2234 \
--port 30303 \
--rpcport 8545 \
--datadir "bdata/node5" \
--nodiscover \
\
--rpc \
--rpccorsdomain "*" \
--rpcapi "eth,net,debug" \
--dev \
--verbosity 5 
