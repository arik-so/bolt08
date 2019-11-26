# bolt08
[![Build Status](https://travis-ci.com/arik-so/bolt08.svg?branch=master)](https://travis-ci.com/arik-so/bolt08)
[![Coverage Status](https://coveralls.io/repos/github/arik-so/bolt08/badge.svg?branch=master)](https://coveralls.io/github/arik-so/bolt08?branch=master)

A utility for interfacing with the TCP-based networking protocol outlined in Lightning Network's BOLT 8. 

## Install

```shell script
npm install bolt08
```

## Usage

In the examples below, each act is serialized and processed separately, with methods such as

```typescript
handshakeHandler.serializeActOne({remotePublicKey});
```

or

```typescript
handshakeHandler.processActTwo(incomingActTwo);
```

However, if you are comfortable with lending the tool some autonomy, you can simply use

```typescript
const output = handshakeHandler.actDynamically({role: Role.RECEIVER, incomingBuffer: inputData});
```

Where `output` will have the properties `responseBuffer`, `unreadBuffer`, and `transmissionHandler`.

If `responseBuffer` is non-empty, you still need to send a message to your peer.

If `unreadBuffer` is non-empty, you have only processed a portion of the incoming message, 
and should be aware of that when you deal with remaining binary buffers.

If `transmissionHandler` is set, you are now equipped to use it to send and receive regular, post-handshake
messages. Key rotations will be taken care of automatically.

## Example

### Initiate Handshake

```typescript
import {Handshake} from 'bolt08';
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
import {Handshake} from 'bolt08';
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

### Interact with an LND Node

You can set up a local TCP server with node and test the connection with a real Lightning node.

#### Initiate Handshake to LND

First, we need to run LND

```shell script
lnd
```

Assuming regtest and an unlocked wallet, let's also extract our identity pubkey

```shell script
lncli -n regtest getinfo
```

In my case, it was `03c8f10269ebe6f67a703b7d934b10592f0a05f83c83571524a3771f5f921b8d3a`, so let's initiate the handshake.

```typescript
import * as net from 'net';
import {Handshake, Role, TransmissionHandler} from 'bolt08';
import * as crypto from 'crypto';

const localPrivateKey = crypto.randomBytes(32);
const remotePublicKey = Buffer.from('03c8f10269ebe6f67a703b7d934b10592f0a05f83c83571524a3771f5f921b8d3a', 'hex');

const client = new net.Socket();

const handshakeHandler = new Handshake({privateKey: localPrivateKey});
let transmissionHandler: TransmissionHandler;
let pendingData = Buffer.alloc(0);

function processIncomingData(data) {
	// there is some unprocessed data that we will prepend to the newly received data for processing
	const inputData = Buffer.concat([pendingData, data]);
	pendingData = Buffer.alloc(0);

	console.log('Processing:');
	console.log(inputData.toString('hex'));

	if (transmissionHandler instanceof TransmissionHandler) {
		const decryptedResponse = transmissionHandler.receive(inputData);
		console.log('Decrypted:');
		console.log(decryptedResponse.toString('hex'));
	} else {
		const output = handshakeHandler.actDynamically({incomingBuffer: inputData});
		if (output.responseBuffer && output.responseBuffer.length > 0) {
			const response = output.responseBuffer;

			console.log('Responding:');
			console.log(response.toString('hex'));
			client.write(response)
		}
		if (output.transmissionHandler && output.transmissionHandler instanceof TransmissionHandler) {
			transmissionHandler = output.transmissionHandler;
		}
		if (output.unreadBuffer && output.unreadBuffer.length > 0) {
			pendingData = output.unreadBuffer;
			// let's immediately process the remaining data in this case
			processIncomingData(Buffer.alloc(0));
		}
	}
}

client.connect(9735, '127.0.0.1', () => {
	console.log('connected');
	const firstActOutput = handshakeHandler.actDynamically({
		role: Role.INITIATOR,
		remotePublicKey
	});
	const firstMessage = firstActOutput.responseBuffer;
	console.log('First message:');
	console.log(firstMessage.toString('hex'));
	client.write(firstMessage);
});

client.on('data', (data) => {
	console.log('Received:');
	console.log(data.toString('hex'));
	processIncomingData(data);
});

client.on('error', (error) => {
	console.log('Error:');
	console.log(error);
});

client.on('close', function () {
	console.log('Connection closed');
});
```

The output might look something like this:

> First message:
> 00039d4e60cd8dd41a2d008e06a114921af1932eb6ab7d50beeca666ed346dd960263b35bb394d0aa3245aa4bbf1a4b7fd0a
> 
> Received:
> 0002a39a406673bdb1797a5d1c1ad794aa77f694b5b1610ff5a409a02583aef2daf7d9c09e4dd3ff41589230d40525ef3bf9
> 
> Processing:
> 0002a39a406673bdb1797a5d1c1ad794aa77f694b5b1610ff5a409a02583aef2daf7d9c09e4dd3ff41589230d40525ef3bf9
> 
> Responding:
> 00d5fb4d6dfbfc8685b863db272d054d7caa04802902c7355a873951405c8142c0f73643d2966b83fb113ff9cc26f4ea800077b1184c0a0a0834f20fb79a781679ce
> 
> Received:
> bf242757aadaa93bf564873cc22031f224e5d2d2e21cdb7cb14b7430e458e75ad1aaf9ceee014cdcbc498c66
> 
> Processing:
> bf242757aadaa93bf564873cc22031f224e5d2d2e21cdb7cb14b7430e458e75ad1aaf9ceee014cdcbc498c66
> 
> Decrypted:
> 00100002220000022281

#### Process Handshake from LND

Alternatively, we can first start listening, and then initiate the handshake using `lncli`. To do so,
we must know the node's public key beforehand. For this setup, we're gonna use a local public 
key `036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7`.

```typescript
import * as net from 'net';
import {Socket} from 'net';
import {Handshake, Role, TransmissionHandler} from 'bolt08';

// publicKey: 036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7
const privateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');
const port = 1337;

const handshakeHandler = new Handshake({privateKey});
let transmissionHandler: TransmissionHandler;
let pendingData = Buffer.alloc(0);

function processIncomingData(data, client: Socket) {
	// there is some unprocessed data that we will prepend to the newly received data for processing
	const inputData = Buffer.concat([pendingData, data]);
	pendingData = Buffer.alloc(0);

	console.log('Processing:');
	console.log(inputData.toString('hex'));

	if (transmissionHandler instanceof TransmissionHandler) {
		const decryptedResponse = transmissionHandler.receive(inputData);
		console.log('Decrypted:');
		console.log(decryptedResponse.toString('hex'));
	} else {
		const output = handshakeHandler.actDynamically({role: Role.RECEIVER, incomingBuffer: inputData});
		if (output.responseBuffer && output.responseBuffer.length > 0) {
			const response = output.responseBuffer;

			console.log('Responding:');
			console.log(response.toString('hex'));
			client.write(response)
		}
		if (output.transmissionHandler && output.transmissionHandler instanceof TransmissionHandler) {
			transmissionHandler = output.transmissionHandler;
		}
		if (output.unreadBuffer && output.unreadBuffer.length > 0) {
			pendingData = output.unreadBuffer;
			// let's immediately process the remaining data in this case
			processIncomingData(Buffer.alloc(0), client);
		}
	}
}

const server = net.createServer(function (client) {

	client.on('data', (data: Buffer) => {
		console.log('Received:');
		console.log(data.toString('hex'));
		processIncomingData(data, client);
	});

	client.on('error', (error) => {
		console.log('Error:');
		console.log(error);
	});

	client.on('close', function () {
		console.log('Connection closed');
	});

});

server.listen(port, '127.0.0.1');
```

Now we initiate the handshake using `lncli`.

```shell script
lncli connect 036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7@127.0.0.1:1337
```

The output from Node might then look something like this:

> Received:
> 00026ef8318ce2124ef03deeb243e28b92befc76db39de95d2809470e9be7ab26fa41b1183c3133c3803c64a271690abb911
> 
> Processing:
> 00026ef8318ce2124ef03deeb243e28b92befc76db39de95d2809470e9be7ab26fa41b1183c3133c3803c64a271690abb911
> 
> Responding:
> 0003a30c775f2f6734d4a179a4ec78116f3a419f5baecc5a62632bf7d83ea080c7884f4c054fb88119f9812d5c2988f881b0
> 
> Received:
> 0039c112d508c1e26d5088e64467e8a57c087e5eae357aa7fa63f48d165b2ff5b8381a21fe79bed61d6454444ba36cf478b0ad22ff53c5bbb34cf42ef4c284549f7a2a83fc6cc9f85eda787ca725fa0c2b89a2dca947ce9ddc5cd629c4c2202252cfc6b96ba06a3f8b1cec7ec3db
> 
> Processing:
> 0039c112d508c1e26d5088e64467e8a57c087e5eae357aa7fa63f48d165b2ff5b8381a21fe79bed61d6454444ba36cf478b0ad22ff53c5bbb34cf42ef4c284549f7a2a83fc6cc9f85eda787ca725fa0c2b89a2dca947ce9ddc5cd629c4c2202252cfc6b96ba06a3f8b1cec7ec3db
> 
> Processing:
> 2a83fc6cc9f85eda787ca725fa0c2b89a2dca947ce9ddc5cd629c4c2202252cfc6b96ba06a3f8b1cec7ec3db
> 
> Decrypted received:
> 00100002220000022281

## License

MIT
