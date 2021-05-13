# Univrse.js

![npm](https://img.shields.io/npm/v/univrse?color=informational)
![License](https://img.shields.io/github/license/libitx/univrse-js?color=informational)
![Build Status](https://img.shields.io/github/workflow/status/libitx/univrse-js/Node.js%20CI)

Universal schema for data serialisation, signing and encryption.

* **Serialising data** - Simple, binary-friendly data exchange using the Concise Binary Object Representation (CBOR) data format.
* **Authenticating data** - Protect integrity of data with digital signatures or message authentication code (MAC) algorithms.
* **Securing data** - Ensure confidentiality and integrity of data for one or multiple recipients, using standardised authenticated encryption algorithms.

## Installation

Install Univrse with npm or yarn:

```shell
npm install univrse
# or
yarn add univrse
```

Alternatively use in a browser via CDN:

```html
<script src="//unpkg.com/univrse/dist/univrse.min.js"></script>
```

Univrse has a peer dependency on version 2 the bsv library which must also be installed in your project.

## Usage

For full documentation, please refer to:

* [univrse.network docs](https://univrse.network/docs)
* [univrse.js API docs](#todo)

### Serialising data

Any arbitrary payload can be wrapped in an `Envelope` structure, and then encoded in one of three serialisation formats:

* `Envelope#toBuffer()` - Concise CBOR-encoded binary value
* `Envelope#toString()` - Compact Base64-url encoded string value
* `Envelope#toScript()` - Encoded in a Bitcoin `OP_RETURN` script

```javascript
import { Envelope } from 'univrse'

// Wrap any arbitrary data payload in an Envelope structure
const payload = 'Hello world!'
const env1 = Envelope.wrap(payload, { proto: 'univrse.demo' })

// Encode the data in one of three serialisation formats
const envBuffer = env1.toBuffer()
const envString = env1.toString()
const envScript = env1.toScript()

// Decode the serialised data back into an Envelope structure
const env2 = Envelope.fromBuffer(envBuffer)
const env3 = Envelope.fromString(envString)
const env4 = Envelope.fromScript(envScript)

// Compare payload
console.log(env2.payload === payload, env3.payload === payload, env4.payload === payload)
// => true, true, true
```

### Using signatures

Digital signatures or message authentication code (MAC) algorithms can be used to protect the integrity of an Envelope's data payload.

```javascript
import { Envelope, Key } from 'univrse'

// Generate keys
const aliceKey = await Key.generate('ec', 'secp256k1')
const alicePubKey = aliceKey.toPublic()
const appSecret = await Key.generate('oct', 256)

// Sign and verify using a single key
const env1 = Envelope.wrap('Hello world!', { proto: 'univrse.demo' })
await env1.sign(aliceKey, { alg: 'ES256K', kid: 'alice' })
const v1 = await env1.verify(alicePub)
console.log(v1)
// => true

// Sign and verify using multiple keys and algorithms
const env2 = Envelope.wrap('Hello world!', { proto: 'univrse.demo' })
await env2.sign([
  [aliceKey, { alg: 'ES256K', kid: 'alice' }],
  [appSecret, { alg: 'HS256', kid: 'app' }]
])
const v2 = await env2.verify([alicePub, appSecret])
console.log(v2)
// => true
```

### Using encryption

Authenticated encryption algorithms may be used to ensure the confidentiality of an Envelope's data payload for one or multiple recipients.

```javascript
import { Envelope, Key } from 'univrse'

// Generate keys
const bobKey = await Key.generate('ec', 'secp256k1')
const bobPubKey = bobKey.toPublic()
const charlieKey = await Key.generate('ec', 'secp256k1')
const charliePubKey = bobKey.toPublic()
const appSecret = await Key.generate('oct', 256)

// Encrypt and decrypt data for a single recipient
const env1 = Envelope.wrap('Hello world!', { proto: 'univrse.demo' })
await env1.encrypt(bobPubKey, { alg: 'ECDH-ES+A128GCM', kid: 'bob' })
await env1.decrypt(bobKey)
console.log(env1.payload)
// => "Hello world!"

// Encrypt and decrypt data for multiple recipients using multiple algorithms
const env2 = Envelope.wrap('Hello world!', { proto: 'univrse.demo' })
await env2.encrypt([
  [appSecret, { alg: 'A256GCM' }],
  [bobPubKey, { alg: 'ECDH-ES+A128GCM', kid: 'bob' }],
  [bobPubKey, { alg: 'ECIES-BIE1', kid: 'charlie' }]
])

const bobEnv = Envelope.fromBuffer(env2.toBuffer())
await bobEnv.decryptAt(1, bobKey)
console.log(bobEnv.payload)
// => "Hello world!"

const charlieEnv = Envelope.fromBuffer(env2.toBuffer())
await charlieEnv.decryptAt(2, charlieKey)
console.log(charlieEnv.payload)
// => "Hello world!"
```

### Working with `bsv` keys

The `util` module provides a number of helper functions to convert to and from `bsv` keys.

```javascript
import { KeyPair } from 'bsv'
import { Key, util } from 'univrse'

// Convert bsv KeyPair to Univrse keys
const keyPair = KeyPair.fromRandom()
const keyFromPrivKey = util.fromBsvPrivKey(keyPair.privKey)
const keyFromPubKey = util.fromBsvPubKey(keyPair.pubKey)

// Convert Univrse key to bsv keys
const key = await Key.generate('ec', 'secp256k1')
const privKey = util.toBsvPrivKey(key)
const pubKey = util.toBsvPubKey(key)
```

## License

Univrse is open source and released under the [Apache-2 License](https://github.com/libitx/univrse-js/blob/master/LICENSE).

Copyright (c) 2021 Chronos Labs Ltd.