./build/bin/geth \
\
--fast \
--networkid 2234 \
--port 30303 \
--nodiscover \
--maxpeers 25 \
--nat "any" \
--datadir "/home/blackzid/Desktop/PBFT_TEST/" \
--autodag \
--pbft \
\
--rpc \
--rpccorsdomain "*" \
\
--jitvm
