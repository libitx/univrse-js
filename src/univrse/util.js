import { Buffer } from 'buffer'
import { Bn, KeyPair, PubKey, Point, PrivKey } from 'bsv'
import Key from './key.js'


/**
 * TODO
 */
 export function fromBsvPubKey(pubKey) {
  return new Key('EC', {
    crv: 'secp256k1',
    x: Buffer.from(pubKey.point.x.toArray('big', 32)),
    y: Buffer.from(pubKey.point.y.toArray('big', 32))
  })
}


/**
 * TODO
 */
export function fromBsvPrivKey(privKey) {
  const { pubKey } = KeyPair.fromPrivKey(privKey)
  return new this('EC', {
    crv: 'secp256k1',
    d: Buffer.from(privKey.bn.toArray('big', 32)),
    x: Buffer.from(pubKey.point.x.toArray('big', 32)),
    y: Buffer.from(pubKey.point.y.toArray('big', 32))
  })
}


/**
 * TODO
 */
 export function toBsvPubKey(key) {
  const x = Bn.fromBuffer(Buffer.from(key.params.x)),
        y = Bn.fromBuffer(Buffer.from(key.params.y));
  
  return new PubKey(new Point(x, y))
}


/**
 * TODO
 */
export function toBsvPrivKey(key) {
  const bn = Bn.fromBuffer(Buffer.from(key.params.d))
  return PrivKey.fromBn(bn)
}