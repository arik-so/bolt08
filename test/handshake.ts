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

		// act 1:
		// chaining_key: accumulated hash of previous ECDH outputs (whatever exactly that means)
		// handshake_hash: accumulated hash of all handshake data, sent and received
		// temporary_keys[0-2]: intermediate keys for AEAD payloads
		// ephemeral_key: new keypair per session
		// static_key: presumably the node's public keypair

		const ephemeralPrivateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');

		const handshake = new Handshake({
			privateKey: localPrivateKey,
			remotePublicKey: remotePublicKey.getEncoded(true)
		});
		const actOneMessage = await handshake.serializeActOne({
			ephemeralPrivateKey: ephemeralPrivateKey
		});
		assert.equal(actOneMessage.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');

		// the roles are flipped
		const receiverHandshake = new Handshake({
			privateKey: remotePrivateKey,
			remotePublicKey: localPublicKey.getEncoded(true)
		});
	})

});
