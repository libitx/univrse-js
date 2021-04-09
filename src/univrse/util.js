import { Buffer } from 'buffer'
import { Bn, PubKey, Point, PrivKey } from 'bsv'


/**
 * TODO
 */
 export function toPubKey(key) {
  const x = Bn.fromBuffer(Buffer.from(key.params.x)),
        y = Bn.fromBuffer(Buffer.from(key.params.y));
  
  return new PubKey(new Point(x, y))
}


/**
 * TODO
 */
export function toPrivKey(key) {
  const bn = Bn.fromBuffer(Buffer.from(key.params.d))
  return PrivKey.fromBn(bn)
}