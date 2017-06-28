function printBlock(block) {
  console.log("Block number     : " + block.number + " "
    + " hash            : " + block.hash + " "
    + " parentHash      : " + block.parentHash + " "
    + " miner           : " + block.miner + " "
    + " size            : " + block.size + " "
    + " gasLimit        : " + block.gasLimit + " "
    + " gasUsed         : " + block.gasUsed + " "
    + " timestamp       : " + block.timestamp + " "
    + " transactions    : " + block.transactions.length + "\n");
}

for (var i = 1; i < 100; i++) {
    block = eth.getBlock(i);
    if (block != null) {
        printBlock(block);
    }
}