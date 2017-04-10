rm -r ./bdata/node/geth
rm -r ./bdata/node/keystore
rm ./bdata/logs/*.log
./go-ethereum/build/bin/geth --datadir "bdata/node" init genesis.json