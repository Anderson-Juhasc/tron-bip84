const { bip32, payments, address } = require('bitcoinjs-lib')
    , bip39 = require('bip39')
    , BIP84 = require('bip84')
    , ethUtil = require('ethereumjs-util')

function fromMnemonic(mnemonic, password, isTestnet) {
  BIP84.fromSeed.call(this, mnemonic, password, isTestnet, 195)
}

fromMnemonic.prototype = Object.create(BIP84.fromSeed.prototype)

function fromZPrv(zprv) {
  BIP84.fromZPrv.call(this, zprv)
}

fromZPrv.prototype = Object.create(BIP84.fromZPrv.prototype)

fromZPrv.prototype.getPrivateKey = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , prvkey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).privateKey

  return prvkey.toString('hex')
}

fromZPrv.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubkey = bip32.fromBase58(this.zprv, this.network).derive(change).derive(index).publicKey
    , ethPubkey = ethUtil.importPublic(pubkey)
    , addressBuffer = ethUtil.publicToAddress(ethPubkey)

  return address.toBase58Check(addressBuffer, 0x41)
}

function fromZPub(zpub) {
  BIP84.fromZPub.call(this, zpub)
}

fromZPub.prototype = Object.create(BIP84.fromZPub.prototype)

fromZPub.prototype.getAddress = function(index, isChange) {
  let change = isChange === true ? 1 : 0
    , pubkey = bip32.fromBase58(this.zpub, this.network).derive(change).derive(index).publicKey
    , ethPubkey = ethUtil.importPublic(pubkey)
    , addressBuffer = ethUtil.publicToAddress(ethPubkey)

  return address.toBase58Check(addressBuffer, 0x41)
}

module.exports = {
  generateMnemonic: bip39.generateMnemonic,
  entropyToMnemonic: bip39.entropyToMnemonic,
  fromMnemonic: fromMnemonic,
  fromZPrv: fromZPrv,
  fromZPub: fromZPub
}
