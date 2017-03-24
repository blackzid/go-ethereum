rm -r ./bdata/node*/geth
rm -r ./bdata/node*/keystore
rm ./bdata/logs/*.log
../build/bin/geth --datadir "bdata/node1" init genesis.json
../build/bin/geth --datadir "bdata/node2" init genesis.json
../build/bin/geth --datadir "bdata/node3" init genesis.json
../build/bin/geth --datadir "bdata/node4" init genesis.json
