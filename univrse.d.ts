type BsvPrivKey = any;
type BsvPubKey = any;
type BsvScript = any;
type CborData = Buffer;
type CborEnvelope = CborData;
type CborKey = CborData;

export interface EncryptionOptions {
  aad?: Buffer | string;
  apu?: Buffer | string;
  apv?: Buffer | string;
  epk?: Buffer;
  iv?: Buffer;
  tag?: Buffer;
}

export interface EnvelopeParams {
  header?: RawHeaders;
  payload?: any;
  signature?: Signature | Signature[];
  recipient?: Recipient | Recipient[];
}

export type EnvelopeTuple = [
  header: RawHeaders,
  payload: any,
  signature?: Signature | Signature[],
  recipient?: Recipient | Recipient[],
]

type EnvelopeString = string;

export class Envelope {
  header: Header;
  payload: any;
  signature?: Signature | Signature[];
  recipient?: Recipient | Recipient[];

  constructor(params: EnvelopeParams);
  static fromArray(parts: EnvelopeTuple): Envelope;
  static fromBuffer(buffer: CborEnvelope): Envelope;
  static fromScript(script: BsvScript): Envelope;
  static fromString(str: EnvelopeString): Envelope;
  static wrap(payload: any, headers?: RawHeaders): Envelope;

  get encodedPayload(): CborData;
  set encodedPayload(payload: CborData);

  decrypt(key: Key, opts?: EncryptionOptions): Promise<this>;
  decryptAt(i: number, key: Key, opts?: EncryptionOptions): Promise<this>;
  decryptAt(i: number, key: Key, opts?: EncryptionOptions): Promise<this>;
  encrypt(key: Key, headers: RawHeaders, opts?: EncryptionOptions): Promise<this>;
  pushRecipient(recipient: Recipient | Recipient[]): this;
  pushSignature(signature: Signature | Signature[]): this;
  sign(key: Key, headers?: RawHeaders): Promise<this>;
  toArray(): EnvelopeTuple;
  toBuffer(): CborEnvelope;
  toScript(): BsvScript;
  toString(): EnvelopeString;
  verify(key: Key, i?: number): Promise<boolean>;
}

export interface RawHeaders {
  alg?: string;
  crit?: string;
  cty?: string;
  iv?: string;
  kid?: string;
  proto?: string;
  zip?: string;
  [key: string]: string;
}

export class Header {
  headers: RawHeaders;

  constructor(headers: RawHeaders);
  static wrap(headers: RawHeaders): Header;
  unwrap(): RawHeaders;
}

export type KeyType = 'ec' | 'oct';

export interface EcKeyParams {
  crv: string;
  d: Buffer;
  x: Buffer;
  y: Buffer;
}

export interface EcKeyObject extends EcKeyParams {
  kty: 'ec';
}

export interface OctKeyParams {
  k: Buffer;
}

export interface OctKeyObject extends OctKeyParams {
  kty: 'oct';
}

export type KeyParams = EcKeyParams | OctKeyParams;

export type KeyObject = EcKeyObject | OctKeyObject;

export class Key {
  type: KeyType;
  params: KeyParams;

  constructor(type: KeyType, params: KeyParams);
  static decode(buf: CborKey): Key;
  static generate(type: KeyType, param: string | number): Promise<Key>;
  encrypt(key: Key, headers: RawHeaders, opts?: EncryptionOptions): Promise<this>;
  toBuffer(): CborKey;
  toObject(): KeyObject;
  toPublic(): Key;
}

export interface RecipientParams {
  header?: RawHeaders;
  key?: Key;
}

export type RecipientTuple = [
  header: Header,
  key?: Key,
]

export declare class Recipient {
  header: RawHeaders;
  key?: Key;

  constructor(params: RecipientParams);
  static fromArray(parts: RecipientTuple | RecipientTuple[]): Recipient | Recipient[];
  static wrap(key: Key, headers?: RawHeaders): Recipient;

  decrypt(key: Key, opts?: EncryptionOptions): Promise<this>;
  toArray(): RecipientTuple;
}

export interface SignatureParams {
  header?: RawHeaders;
  signature?: Buffer;
}

export type SignatureTuple = [
  header: RawHeaders,
  signature: Buffer,
]

export class Signature {
  header: Header;
  signature: Buffer;

  constructor(params: SignatureParams);
  static fromArray(parts: SignatureTuple | SignatureTuple[]): Signature | Signature[];
  static wrap(key: Key, headers?: RawHeaders): Signature;

  toArray(): SignatureTuple;
}

export namespace util {
  function fromBsvPubKey(pubKey: BsvPubKey): Key;
  function fromBsvPrivKey(privKey: BsvPrivKey): Key;
  function toBsvPubKey(key: Key): BsvPubKey;
  function toBsvPrivKey(key: Key): BsvPrivKey;
}

export const version: string;
