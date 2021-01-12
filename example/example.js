const Vapash = require('../index.js')

var vapash = new Vapash()
// make the 1000 cache items with a seed of 0 * 32
vapash.mkcache(1000, new Buffer(32).fill(0))

var result = vapash.run(new Buffer('test'), new Buffer([0]), 1000)
console.log(result.hash.toString('hex'))
