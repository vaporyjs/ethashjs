const Vapash = require('../index.js')
const vapHashUtil = require('../util.js')
const vapUtil = require('vaporyjs-util')
const Header = require('vaporyjs-block/header.js')
const tape = require('tape')
const powTests = require('vaporyjs-testing').tests.powTests.vapash_tests

var vapash = new Vapash()
var tests = Object.keys(powTests)

tape('POW tests', function (t) {
  tests.forEach(function (key) {
    var test = powTests[key]
    var header = new Header(new Buffer(test.header, 'hex'))

    var headerHash = vapash.headerHash(header.raw)
    t.equal(headerHash.toString('hex'), test.header_hash, 'generate header hash')

    var epoc = vapHashUtil.getEpoc(vapUtil.bufferToInt(header.number))
    t.equal(vapHashUtil.getCacheSize(epoc), test.cache_size, 'generate cache size')
    t.equal(vapHashUtil.getFullSize(epoc), test.full_size, 'generate full cache size')

    vapash.mkcache(test.cache_size, new Buffer(test.seed, 'hex'))
    t.equal(vapash.cacheHash().toString('hex'), test.cache_hash, 'generate cache')

    var r = vapash.run(headerHash, new Buffer(test.nonce, 'hex'), test.full_size)
    t.equal(r.hash.toString('hex'), test.result, 'generate result')
    t.equal(r.mix.toString('hex'), test.mixhash, 'generate mix hash')
  })
  t.end()
})
