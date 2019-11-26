# bolt08
[![Build Status](https://travis-ci.com/arik-so/bolt08.svg?branch=master)](https://travis-ci.com/arik-so/bolt08)
[![Coverage Status](https://coveralls.io/repos/github/arik-so/bolt08/badge.svg?branch=master)](https://coveralls.io/github/arik-so/bolt08?branch=master)

A utility for interfacing with the TCP-based networking protocol outlined in Lightning Network's BOLT 8. 

## Install

```shell script
npm install bolt08
```

## Example

### Initiate Handshake

```typescript
import Handshake from 'bolt08';
import * as crypto from 'crypto';

// we initialize a new node instance with a local private key
const privateKey = crypto.randomBytes(32);
const handshakeHandler = new Handshake({privateKey});

// we know the counterparty's public key, so we initiate the connection
const remotePublicKey = Buffer.from('028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7', 'hex');
const actOne = handshakeHandler.serializeActOne({remotePublicKey});

// we send act one to the remote party, and receive their act two response
// we do not go into detail for how the transmission is facilitated through TCP
const incomingActTwo: Buffer = oracle.sendAndReceive(actOne);
handshakeHandler.processActTwo(incomingActTwo);

// now we perform the final act
const actThree = handshakeHandler.serializeActThree();
oracle.send(actThree); // we do not care about the response

// having performed act three, we can now send messages back and forth
const transmissionHandler = handshakeHandler.transmissionHandler;

const message = Buffer.from('Hello World!', 'ascii');
const serializedMessage = transmissionHandler.send(message); // serializedMessage is what we send over TCP
```

### Respond to Handshake

```typescript
import Handshake from 'bolt08';
import * as crypto from 'crypto';

// we initialize a new node instance with a local private key
const privateKey = crypto.randomBytes(32);
const handshakeHandler = new Handshake({privateKey});

const incomingActOne: Buffer = oracle.receive();
handshakeHandler.processActOne(incomingActOne);

const actTwo = handshakeHandler.serializeActTwo({});
const incomingActThree = oracle.sendAndReceive(actTwo);

handshakeHandler.processActThree(incomingActThree);

// having processed act three, we can now send messages back and forth
const transmissionHandler = handshakeHandler.transmissionHandler;

const message = Buffer.from('Welcome!', 'ascii');
const serializedMessage = transmissionHandler.send(message); // serializedMessage is what we send over TCP
```

## License

MIT
