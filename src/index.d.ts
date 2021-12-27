type BsvPrivKey = any;
type BsvPubKey = any;
type BsvScript = any;
type CborData = Buffer;
type CborEnvelope = CborData;
type CborKey = CborData;
type B64Envelope = string;

interface EncryptionOptions {
  aad?: Buffer | string;
  apu?: Buffer | string;
  apv?: Buffer | string;
  epk?: Buffer;
  iv?: Buffer;
  tag?: Buffer;
}

interface EnvelopeParams {
  headers?: RawHeaders;
  payload?: any;
  signature?: Signature | Signature[];
  recipient?: Recipient | Recipient[];
}

type EnvelopeTuple = [
  header: RawHeaders,
  payload: any,
  signature?: Signature | Signature[],
  recipient?: Recipient | Recipient[],
]

declare class Envelope {
  header: Header;
  payload: any;
  signature?: Signature | Signature[];
  recipient?: Recipient | Recipient[];

  constructor(params: EnvelopeParams);
  static fromArray(parts: EnvelopeTuple): Envelope;
  static fromBuffer(buffer: CborEnvelope): Envelope;
  static fromScript(script: BsvScript): Envelope;
  static fromString(str: B64Envelope): Envelope;
  static wrap(payload: any, headers?: RawHeaders): Envelope;

  get encodedPayload(): CborData;
  set encodedPayload(payload: CborData);

  decrypt(key: Key, opts?: EncryptionOptions): Promise<this>;
  decryptAt(i: number, key: Key, opts?: EncryptionOptions): Promise<this>;
  decryptAt(i: number, key: Key, opts?: EncryptionOptions): Promise<this>;
  encrypt(key: Key | KeyList, headers?: RawHeaders, opts?: EncryptionOptions): Promise<this>;
  pushRecipient(recipient: Recipient | Recipient[]): this;
  pushSignature(signature: Signature | Signature[]): this;
  sign(key: Key | KeyList, headers?: RawHeaders): Promise<this>;
  toArray(): EnvelopeTuple;
  toBuffer(): CborEnvelope;
  toScript(): BsvScript;
  toString(): B64Envelope;
  verify(key: Key, i?: number): Promise<boolean>;
}

interface RawHeaders {
  alg?: string;
  crit?: string;
  cty?: string;
  iv?: string;
  kid?: string;
  proto?: string;
  zip?: string;
  [key: string]: any;
}

declare class Header {
  headers: RawHeaders;

  constructor(headers: RawHeaders);
  static wrap(headers: RawHeaders): Header;
  unwrap(): RawHeaders;
}

type KeyType = 'ec' | 'oct';

interface EcKeyParams {
  crv: string;
  d: Buffer;
  x: Buffer;
  y: Buffer;
}
interface OctKeyParams {
  k: Buffer;
}

type KeyParams = EcKeyParams | OctKeyParams;

type KeyObject = KeyParams & {
  kty: KeyType;
};

declare class Key {
  type: KeyType;
  params: KeyParams;

  constructor(type: KeyType, params: KeyParams);
  static decode(buf: CborKey): Key;
  static generate(type: KeyType, param: 'secp256k1' | 128 | 256 | 512): Promise<Key>;
  encrypt(key: Key, headers: RawHeaders, opts?: EncryptionOptions): Promise<Recipient>;
  toBuffer(): CborKey;
  toObject(): KeyObject;
  toPublic(): Key;
}

type KeyTuple = [
  key: Key,
  headers: RawHeaders
]

type KeyList = Key[] | KeyTuple[]

interface RecipientParams {
  header?: RawHeaders;
  key?: Key;
}

type RecipientTuple = [
  header: Header,
  key?: Key,
]

declare class Recipient {
  header: RawHeaders;
  key?: Key;

  constructor(params: RecipientParams);
  static fromArray(parts: RecipientTuple | RecipientTuple[]): Recipient | Recipient[];
  static wrap(key: Key, headers?: RawHeaders): Recipient;

  decrypt(key: Key, opts?: EncryptionOptions): Promise<this>;
  toArray(): RecipientTuple;
}

interface SignatureParams {
  header?: RawHeaders;
  signature?: Buffer;
}

type SignatureTuple = [
  header: RawHeaders,
  signature: Buffer,
]

declare class Signature {
  header: Header;
  signature: Buffer;

  constructor(params: SignatureParams);
  static fromArray(parts: SignatureTuple | SignatureTuple[]): Signature | Signature[];
  static wrap(key: Key, headers?: RawHeaders): Signature;

  toArray(): SignatureTuple;
}

declare namespace util {
  function fromBsvPubKey(pubKey: BsvPubKey): Key;
  function fromBsvPrivKey(privKey: BsvPrivKey): Key;
  function toBsvPubKey(key: Key): BsvPubKey;
  function toBsvPrivKey(key: Key): BsvPrivKey;
}

export {
  Envelope,
  Header,
  Key,
  Recipient,
  Signature,
  util
};
export const version: string;