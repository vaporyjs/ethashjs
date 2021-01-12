const vapUtil = require('vaporyjs-util')
const vapHashUtil = require('./util.js')
const xor = require('buffer-xor')
const BN = vapUtil.BN
const async = require('async')

var Vapash = module.exports = function (cacheDB) {
  this.dbOpts = {
    valueEncoding: 'json'
  }
  this.cacheDB = cacheDB
  this.cache = false
}

Vapash.prototype.mkcache = function (cacheSize, seed) {
  // console.log('generating cache')
  // console.log('size: ' + cacheSize)
  // console.log('seed: ' + seed.toString('hex'))
  const n = Math.floor(cacheSize / vapHashUtil.params.HASH_BYTES)
  var o = [vapUtil.sha3(seed, 512)]

  var i
  for (i = 1; i < n; i++) {
    o.push(vapUtil.sha3(o[o.length - 1], 512))
  }

  for (var _ = 0; _ < vapHashUtil.params.CACHE_ROUNDS; _++) {
    for (i = 0; i < n; i++) {
      var v = o[i].readUInt32LE(0) % n
      o[i] = vapUtil.sha3(xor(o[(i - 1 + n) % n], o[v]), 512)
    }
  }

  this.cache = o
  return this.cache
}

Vapash.prototype.calcDatasetItem = function (i) {
  const n = this.cache.length
  const r = Math.floor(vapHashUtil.params.HASH_BYTES / vapHashUtil.params.WORD_BYTES)
  var mix = new Buffer(this.cache[i % n])
  mix.writeInt32LE(mix.readUInt32LE(0) ^ i, 0)
  mix = vapUtil.sha3(mix, 512)
  for (var j = 0; j < vapHashUtil.params.DATASET_PARENTS; j++) {
    var cacheIndex = vapHashUtil.fnv(i ^ j, mix.readUInt32LE(j % r * 4))
    mix = vapHashUtil.fnvBuffer(mix, this.cache[cacheIndex % n])
  }
  return vapUtil.sha3(mix, 512)
}

Vapash.prototype.run = function (val, nonce, fullSize) {
  fullSize = fullSize || this.fullSize
  const n = Math.floor(fullSize / vapHashUtil.params.HASH_BYTES)
  const w = Math.floor(vapHashUtil.params.MIX_BYTES / vapHashUtil.params.WORD_BYTES)
  const s = vapUtil.sha3(Buffer.concat([val, vapHashUtil.bufReverse(nonce)]), 512)
  const mixhashes = Math.floor(vapHashUtil.params.MIX_BYTES / vapHashUtil.params.HASH_BYTES)
  var mix = Buffer.concat(Array(mixhashes).fill(s))

  var i
  for (i = 0; i < vapHashUtil.params.ACCESSES; i++) {
    var p = vapHashUtil.fnv(i ^ s.readUInt32LE(0), mix.readUInt32LE(i % w * 4)) % Math.floor(n / mixhashes) * mixhashes
    var newdata = []
    for (var j = 0; j < mixhashes; j++) {
      newdata.push(this.calcDatasetItem(p + j))
    }

    newdata = Buffer.concat(newdata)
    mix = vapHashUtil.fnvBuffer(mix, newdata)
  }

  var cmix = new Buffer(mix.length / 4)
  for (i = 0; i < mix.length / 4; i = i + 4) {
    var a = vapHashUtil.fnv(mix.readUInt32LE(i * 4), mix.readUInt32LE((i + 1) * 4))
    var b = vapHashUtil.fnv(a, mix.readUInt32LE((i + 2) * 4))
    var c = vapHashUtil.fnv(b, mix.readUInt32LE((i + 3) * 4))
    cmix.writeUInt32LE(c, i)
  }

  return {
    mix: cmix,
    hash: vapUtil.sha3(Buffer.concat([s, cmix]))
  }
}

Vapash.prototype.cacheHash = function () {
  return vapUtil.sha3(Buffer.concat(this.cache))
}

Vapash.prototype.headerHash = function (header) {
  return vapUtil.rlphash(header.slice(0, -2))
}

/**
 * Loads the seed and the cache given a block nnumber
 * @method loadEpoc
 * @param number Number
 * @param cm function
 */
Vapash.prototype.loadEpoc = function (number, cb) {
  var self = this
  const epoc = vapHashUtil.getEpoc(number)

  if (this.epoc === epoc) {
    return cb()
  }

  this.epoc = epoc

  // gives the seed the first epoc found
  function findLastSeed (epoc, cb2) {
    if (epoc === 0) {
      return cb2(vapUtil.zeros(32), 0)
    }

    self.cacheDB.get(epoc, self.dbOpts, function (err, data) {
      if (!err) {
        cb2(data.seed, epoc)
      } else {
        findLastSeed(epoc - 1, cb2)
      }
    })
  }

  /* eslint-disable handle-callback-err */
  self.cacheDB.get(epoc, self.dbOpts, function (err, data) {
    if (!data) {
      self.cacheSize = vapHashUtil.getCacheSize(epoc)
      self.fullSize = vapHashUtil.getFullSize(epoc)

      findLastSeed(epoc, function (seed, foundEpoc) {
        self.seed = vapHashUtil.getSeed(seed, foundEpoc, epoc)
        var cache = self.mkcache(self.cacheSize, self.seed)
        // store the generated cache
        self.cacheDB.put(epoc, {
          cacheSize: self.cacheSize,
          fullSize: self.fullSize,
          seed: self.seed,
          cache: cache
        }, self.dbOpts, cb)
      })
    } else {
      // Object.assign(self, data)
      self.cache = data.cache.map(function (a) {
        return new Buffer(a)
      })
      self.cacheSize = data.cacheSize
      self.fullSize = data.fullSize
      self.seed = new Buffer(data.seed)
      cb()
    }
  })
  /* eslint-enable handle-callback-err */
}

Vapash.prototype._verifyPOW = function (header, cb) {
  var self = this
  var headerHash = this.headerHash(header.raw)
  var number = vapUtil.bufferToInt(header.number)

  this.loadEpoc(number, function () {
    var a = self.run(headerHash, new Buffer(header.nonce, 'hex'))
    var result = new BN(a.hash)
    cb(a.mix.toString('hex') === header.mixHash.toString('hex') && (vapUtil.TWO_POW256.div(new BN(header.difficulty)).cmp(result) === 1))
  })
}

Vapash.prototype.verifyPOW = function (block, cb) {
  var self = this
  var valid = true

  // don't validate genesis blocks
  if (block.header.isGenesis()) {
    cb(true)
    return
  }

  this._verifyPOW(block.header, function (valid2) {
    valid &= valid2

    if (!valid) {
      return cb(valid)
    }

    async.eachSeries(block.uncleHeaders, function (uheader, cb2) {
      self._verifyPOW(uheader, function (valid3) {
        valid &= valid3
        if (!valid) {
          cb2(Boolean(valid))
        } else {
          cb2()
        }
      })
    }, function () {
      cb(Boolean(valid))
    })
  })
}
