const Vapash = require('..')
const levelup = require('levelup')
const memdown = require('memdown')

Vapash.prototype.verifySubmit = function (number, headerHash, nonce, cb) {
  var self = this
  console.log(number)
  this.loadEpoc(number, function () {
    console.log('EPOC set')
    console.log(self.seed.toString('hex'))
    var a = self.run(headerHash, new Buffer(nonce, 'hex'))
    cb(a.hash)
  })
}

var cacheDB = levelup('', {
  db: memdown
})

var vapash = new Vapash(cacheDB)

var header = Buffer('0e2887aa1a0668bf8254d1a6ae518927de99e3e5d7f30fd1f16096e2608fe05e', 'hex')

vapash.verifySubmit(35414, header, 'e360b6170c229d15', function (result) {
  console.log(result.toString('hex'))
})
