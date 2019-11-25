import * as crypto from 'crypto';
import Bigi = require('bigi');
import chai = require('chai');
import ecurve = require('ecurve');
import Handshake, {HandshakeHash} from '../src/handshake';

const assert = chai.assert;
const secp256k1 = ecurve.getCurveByName('secp256k1');

describe('Handshake Tests', () => {

	it('should simulate the handshake', async () => {
		// act 1:
		// chaining_key: accumulated hash of previous ECDH outputs (whatever exactly that means)
		// handshake_hash: accumulated hash of all handshake data, sent and received
		// temporary_keys[0-2]: intermediate keys for AEAD payloads
		// ephemeral_key: new keypair per session
		// static_key: presumably the node's public keypair

		// the counterparty's pubkey is known a priori
		const localPrivateKey = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex');
		const remotePrivateKey = Buffer.from('2121212121212121212121212121212121212121212121212121212121212121', 'hex');

		const localPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(localPrivateKey));
		const remotePublicKey = secp256k1.G.multiply(Bigi.fromBuffer(remotePrivateKey));

		// step 0:
		// initialize state
		const protocolName = Buffer.from('Noise_XK_secp256k1_ChaChaPoly_SHA256', 'ascii');
		let chainingKey = crypto.createHash('sha256').update(protocolName).digest();
		const prologue = Buffer.from('lightning', 'ascii');
		const handshakeHash = new HandshakeHash(Buffer.concat([chainingKey, prologue]));
		handshakeHash.update(remotePublicKey.getEncoded(true));

		// step 1:
		// generate key
		const ephemeralPrivateKey = Buffer.from('1212121212121212121212121212121212121212121212121212121212121212', 'hex');
		const ephemeralPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(ephemeralPrivateKey));
		handshakeHash.update(ephemeralPublicKey.getEncoded(true));
		const ephemeralSecretPreimage = remotePublicKey.multiply(Bigi.fromBuffer(ephemeralPrivateKey));
		const ephemeralSecret = crypto.createHash('sha256').update(ephemeralSecretPreimage.getEncoded(true)).digest();

		const derivative = await Handshake.hkdf(chainingKey, ephemeralSecret);
		chainingKey = derivative.slice(0, 32);
		const temporaryKey1 = derivative.slice(32);

		const chachaStream = Handshake.encryptWithAD(temporaryKey1, BigInt(0), handshakeHash.value, '');
		handshakeHash.update(chachaStream);
		const message = Buffer.concat([Buffer.alloc(1, 0), ephemeralPublicKey.getEncoded(true), chachaStream]);
		assert.equal(message.toString('hex'), '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a');
	})

});
