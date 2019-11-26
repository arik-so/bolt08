import * as crypto from 'crypto';
import Bigi = require('bigi');
import chai = require('chai');
import ecurve = require('ecurve');
import Handshake from '../src/handshake';

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

			// SEND
			{
				actThreeMessage = await senderHandshake.serializeActThree();
				// assert.equal(actOneMessage.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');
			}

			// RECEIVE
			{
				// the roles are flipped

				// await receiverHandshake.processActOne(actOneMessage);
				// assert.equal(receiverHandshake['hash'].value.toString('hex'), '9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce');
			}
		}
	})

});
