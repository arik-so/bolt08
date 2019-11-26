import * as crypto from 'crypto';
import Bigi = require('bigi');
import chai = require('chai');
import ecurve = require('ecurve');
import Handshake from '../src/handshake';
import TransmissionHandler from '../src/transmission_handler';

const assert = chai.assert;
const secp256k1 = ecurve.getCurveByName('secp256k1');

describe('Handshake Tests', () => {

	it('should simulate the handshake', async () => {
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

		// ACT 1:
		{
			let actOneMessage;

			// SEND
			{
				const ephemeralPrivateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');

				actOneMessage = await senderHandshake.serializeActOne({
					ephemeralPrivateKey: ephemeralPrivateKey,
					remotePublicKey: remotePublicKey.getEncoded(true)
				});
				assert.equal(actOneMessage.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');
			}

			// RECEIVE
			{
				// the roles are flipped

				await receiverHandshake.processActOne(actOneMessage);
				assert.equal(receiverHandshake['hash'].value.toString('hex'), '9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce');
			}
		}

		// ACT 2:
		{
			let actTwoMessage;

			// SEND
			{
				const ephemeralPrivateKey = Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex');
				actTwoMessage = await receiverHandshake.serializeActTwo({ephemeralPrivateKey});
				assert.equal(actTwoMessage.toString('hex'), '0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae');
			}

			// RECEIVE
			{
				await senderHandshake.processActTwo(actTwoMessage);
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
				actThreeMessage = await senderHandshake.serializeActThree();
				assert.equal(actThreeMessage.toString('hex'), '00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba');
				senderTxHandler = senderHandshake.transmissionHandler;
			}

			// RECEIVE
			{
				await receiverHandshake.processActThree(actThreeMessage);
				receiverTxHandler = receiverHandshake.transmissionHandler;
			}

			assert.equal(senderTxHandler['sendingKey'].toString('hex'), receiverTxHandler['receivingKey'].toString('hex'));
			assert.equal(receiverTxHandler['sendingKey'].toString('hex'), senderTxHandler['receivingKey'].toString('hex'));

			// conduct bilateral encoding test
			const randomMessage = crypto.randomBytes(100);
			const encryptedMessage = await receiverTxHandler.send(randomMessage);
			const receivedMessage = await senderTxHandler.receive(encryptedMessage);
			assert.equal(randomMessage.toString('hex'), receivedMessage.toString('hex'));
		}
	});

	it('should simulate a transmission', async () => {
		const chainingKey = Buffer.from('919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01', 'hex');
		const sendingKey = Buffer.from('969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9', 'hex');
		const receivingKey = Buffer.from('bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442', 'hex');
		const txHandler = new TransmissionHandler({chainingKey, sendingKey, receivingKey});

		const message = Buffer.from('68656c6c6f', 'hex');
		const messageBuffers: Buffer[] = [];

		for (let i = 0; i < 1002; i++) {
			messageBuffers[i] = await txHandler.send(message);
		}

		assert.equal(messageBuffers[0].toString('hex'), 'cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95');
		assert.equal(messageBuffers[1].toString('hex'), '72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1');
		assert.equal(messageBuffers[500].toString('hex'), '178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8');
		assert.equal(messageBuffers[501].toString('hex'), '1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd');
		assert.equal(messageBuffers[1000].toString('hex'), '4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09');
		assert.equal(messageBuffers[1001].toString('hex'), '2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36');
	});

});
