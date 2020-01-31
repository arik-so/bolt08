import * as crypto from 'crypto';
import Handshake, {Role} from '../src/handshake';
import TransmissionHandler from '../src/transmission_handler';
import Bigi = require('bigi');
import chai = require('chai');
import ecurve = require('ecurve');

const assert = chai.assert;
const secp256k1 = ecurve.getCurveByName('secp256k1');

describe('Handshake Tests', () => {

	it('should simulate the handshake', () => {
		// the counterparty's pubkey is known a priori
		const localPrivateKey = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex');
		const localPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(localPrivateKey));

		const remotePrivateKey = Buffer.from('2121212121212121212121212121212121212121212121212121212121212121', 'hex');
		const remotePublicKey = secp256k1.G.multiply(Bigi.fromBuffer(remotePrivateKey));

		console.log('GHELLO!');

		// ACT 1:
		// chaining_key: accumulated hash of previous ECDH outputs (whatever exactly that means)
		// handshake_hash: accumulated hash of all handshake data, sent and received
		// temporary_keys[0-2]: intermediate keys for AEAD payloads
		// ephemeral_key: new keypair per session
		// static_key: presumably the node's public keypair

		const senderHandshake = new Handshake({privateKey: localPrivateKey});
		const receiverHandshake = new Handshake({privateKey: remotePrivateKey});

		// ACT 1:
		{
			let actOneMessage;

			// SEND
			{
				const ephemeralPrivateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');

				actOneMessage = senderHandshake.serializeActOne({
					ephemeralPrivateKey: ephemeralPrivateKey,
					remotePublicKey: remotePublicKey.getEncoded(true)
				});
				assert.equal(actOneMessage.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');
			}

			// RECEIVE
			{
				// the roles are flipped

				receiverHandshake.processActOne(actOneMessage);
				assert.equal(receiverHandshake['hash'].value.toString('hex'), '9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce');
			}
		}

		// ACT 2:
		{
			let actTwoMessage;

			// SEND
			{
				const ephemeralPrivateKey = Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex');
				actTwoMessage = receiverHandshake.serializeActTwo({ephemeralPrivateKey});
				assert.equal(actTwoMessage.toString('hex'), '0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae');
			}

			// RECEIVE
			{
				senderHandshake.processActTwo(actTwoMessage);
				assert.equal(senderHandshake['hash'].value.toString('hex'), '90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72');
			}
		}

		// Act 3:
		{
			let actThreeMessage;
			let senderTxHandler: TransmissionHandler;
			let receiverTxHandler: TransmissionHandler;

			// SEND
			{
				actThreeMessage = senderHandshake.serializeActThree();
				assert.equal(actThreeMessage.toString('hex'), '00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba');
				senderTxHandler = senderHandshake.transmissionHandler;
			}

			// RECEIVE
			{
				receiverHandshake.processActThree(actThreeMessage);
				receiverTxHandler = receiverHandshake.transmissionHandler;
			}

			assert.equal(senderTxHandler['sendingKey'].toString('hex'), '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9');
			assert.equal(senderTxHandler['receivingKey'].toString('hex'), 'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442');

			assert.equal(senderTxHandler['sendingKey'].toString('hex'), receiverTxHandler['receivingKey'].toString('hex'));
			assert.equal(receiverTxHandler['sendingKey'].toString('hex'), senderTxHandler['receivingKey'].toString('hex'));

			// conduct bilateral encoding test
			const randomMessage = crypto.randomBytes(100);
			const encryptedMessage = receiverTxHandler.send(randomMessage);
			const receivedMessage = senderTxHandler.receive(encryptedMessage);
			assert.equal(randomMessage.toString('hex'), receivedMessage.message.toString('hex'));
			assert.equal(receivedMessage.unreadBuffer.length, 0);
		}
	});

	it('should simulate the handshake dynamically', () => {
		// the counterparty's pubkey is known a priori
		const localPrivateKey = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex');
		const localPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(localPrivateKey));

		const remotePrivateKey = Buffer.from('2121212121212121212121212121212121212121212121212121212121212121', 'hex');
		const remotePublicKey = secp256k1.G.multiply(Bigi.fromBuffer(remotePrivateKey));

		// ACT 1:
		// chaining_key: accumulated hash of previous ECDH outputs (whatever exactly that means)
		// handshake_hash: accumulated hash of all handshake data, sent and received
		// temporary_keys[0-2]: intermediate keys for AEAD payloads
		// ephemeral_key: new keypair per session
		// static_key: presumably the node's public keypair

		const senderHandshake = new Handshake({privateKey: localPrivateKey});
		const receiverHandshake = new Handshake({privateKey: remotePrivateKey});

		let senderOutput: any;
		let receiverOutput: any;

		// ACT 1:
		{

			// SEND
			{
				const ephemeralPrivateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');

				senderOutput = senderHandshake.actDynamically({
					role: Role.INITIATOR,
					ephemeralPrivateKey,
					remotePublicKey: remotePublicKey.getEncoded(true)
				});
				assert.equal(senderOutput.responseBuffer.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');
			}

			// RECEIVE
			{
				// the roles are flipped
				const ephemeralPrivateKey = Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex');
				receiverOutput = receiverHandshake.actDynamically({
					role: Role.RECEIVER,
					ephemeralPrivateKey,
					incomingBuffer: senderOutput.responseBuffer
				});
				assert.equal(receiverOutput.responseBuffer.toString('hex'), '0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae');
			}
		}

		// ACT 2:
		{

			// RECEIVE
			{
				senderOutput = senderHandshake.actDynamically({
					incomingBuffer: receiverOutput.responseBuffer
				});
				assert.equal(senderOutput.responseBuffer.toString('hex'), '00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba');
			}
		}

		// Act 3:
		{

			// RECEIVE
			{
				receiverOutput = receiverHandshake.actDynamically({
					incomingBuffer: senderOutput.responseBuffer
				});
			}

			const senderTxHandler: TransmissionHandler = senderOutput.transmissionHandler;
			const receiverTxHandler: TransmissionHandler = receiverOutput.transmissionHandler;

			assert.equal(senderTxHandler['sendingKey'].toString('hex'), '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9');
			assert.equal(senderTxHandler['receivingKey'].toString('hex'), 'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442');

			assert.equal(senderTxHandler['sendingKey'].toString('hex'), receiverTxHandler['receivingKey'].toString('hex'));
			assert.equal(receiverTxHandler['sendingKey'].toString('hex'), senderTxHandler['receivingKey'].toString('hex'));

			// conduct bilateral encoding test
			const randomMessage = crypto.randomBytes(100);
			const encryptedMessage = receiverTxHandler.send(randomMessage);
			const receivedMessage = senderTxHandler.receive(encryptedMessage);
			assert.equal(randomMessage.toString('hex'), receivedMessage.message.toString('hex'));
			assert.equal(receivedMessage.unreadBuffer.length, 0);
		}
	});

});
