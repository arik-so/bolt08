import bigintBuffer = require('bigint-buffer');
import Bigi = require('bigi');
import chacha = require('chacha');
import debugModule = require('debug');
import ecurve = require('ecurve');
import * as crypto from 'crypto';
import {Point} from 'ecurve';
import TransmissionHandler from './transmission_handler';
import HKDF from './hkdf';

const debug = debugModule('bolt08:handshake');
const secp256k1 = ecurve.getCurveByName('secp256k1');

enum Role {
	INITIATOR,
	RECEIVER
}

/**
 * Protocol for handling the key setup
 */
export default class Handshake {

	private role?: Role;

	private privateKey: Bigi;
	private publicKey: Point;

	private ephemeralPrivateKey: Bigi;
	private ephemeralPublicKey: Point;

	private remotePublicKey: Point;
	private remoteEphemeralKey: Point;

	private temporaryKeys: Buffer[] = [];

	private hash: HandshakeHash;
	private chainingKey: Buffer;

	private txHandler: TransmissionHandler;

	constructor({privateKey = null}: { privateKey?: Buffer }) {
		if (!privateKey) {
			privateKey = crypto.randomBytes(32);
		}
		this.privateKey = Bigi.fromBuffer(privateKey);
		this.publicKey = secp256k1.G.multiply(this.privateKey);

		// initialize handshake hash
		const protocolName = Buffer.from('Noise_XK_secp256k1_ChaChaPoly_SHA256', 'ascii');
		this.chainingKey = crypto.createHash('sha256').update(protocolName).digest();
		const prologue = Buffer.from('lightning', 'ascii');
		this.hash = new HandshakeHash(Buffer.concat([this.chainingKey, prologue]));
	}

	public get transmissionHandler(): TransmissionHandler {
		if (!this.txHandler) {
			throw new Error('act 3 must be completed before a transmission handler is available');
		}
		return this.txHandler;
	}

	private assumeRole(role: Role) {
		if (this.role in Role) {
			throw new Error('roles cannot change!');
		}
		this.role = role;
	}

	private assertRole(role: Role) {
		if (this.role !== role) {
			throw new Error('invalid action for role!');
		}
	}

	public serializeActOne({ephemeralPrivateKey = null, remotePublicKey}: { ephemeralPrivateKey?: Buffer, remotePublicKey: Buffer }): Buffer {
		this.assumeRole(Role.INITIATOR);
		this.remotePublicKey = Point.decodeFrom(secp256k1, remotePublicKey);
		this.hash.update(this.remotePublicKey.getEncoded(true));

		if (!ephemeralPrivateKey) {
			ephemeralPrivateKey = crypto.randomBytes(32);
		}

		const ephemeralPrivateKeyInteger = Bigi.fromBuffer(ephemeralPrivateKey);
		return this.serializeActMessage({
			actIndex: 0,
			ephemeralPrivateKey: ephemeralPrivateKeyInteger,
			peerPublicKey: this.remotePublicKey
		});
	}

	public processActOne(actOneMessage: Buffer) {
		this.assumeRole(Role.RECEIVER);
		this.hash.update(this.publicKey.getEncoded(true));

		this.remoteEphemeralKey = this.processActMessage({
			actIndex: 0,
			message: actOneMessage,
			localPrivateKey: this.privateKey
		});
	}

	public serializeActTwo({ephemeralPrivateKey = null}: { ephemeralPrivateKey?: Buffer }): Buffer {
		this.assertRole(Role.RECEIVER);

		if (!ephemeralPrivateKey) {
			ephemeralPrivateKey = crypto.randomBytes(32);
		}

		const ephemeralPrivateKeyInteger = Bigi.fromBuffer(ephemeralPrivateKey);
		return this.serializeActMessage({
			actIndex: 1,
			ephemeralPrivateKey: ephemeralPrivateKeyInteger,
			peerPublicKey: this.remoteEphemeralKey
		});
	}

	public processActTwo(actTwoMessage: Buffer) {
		this.assertRole(Role.INITIATOR);
		this.remoteEphemeralKey = this.processActMessage({
			actIndex: 1,
			message: actTwoMessage,
			localPrivateKey: this.ephemeralPrivateKey
		});
	}

	public serializeActThree(): Buffer {
		this.assertRole(Role.INITIATOR);

		// do the stuff here
		const temporaryKey = this.temporaryKeys[1]; // from the second act
		const chacha = Handshake.encryptWithAD(temporaryKey, BigInt(1), this.hash.value, this.publicKey.getEncoded(true));
		debug('Act 3 chacha: %s', chacha.toString('hex'));

		this.hash.update(chacha);

		const sharedSecret = Handshake.ecdh({
			privateKey: this.privateKey,
			publicKey: this.remoteEphemeralKey
		});

		const derivative = Handshake.hkdf(this.chainingKey, sharedSecret);
		this.chainingKey = derivative.slice(0, 32);
		this.temporaryKeys[2] = derivative.slice(32);

		const tag = Handshake.encryptWithAD(this.temporaryKeys[2], BigInt(0), this.hash.value, Buffer.alloc(0));

		const transmissionKeys = Handshake.hkdf(this.chainingKey, Buffer.alloc(0));
		const sendingKey = transmissionKeys.slice(0, 32);
		const receivingKey = transmissionKeys.slice(32);

		this.txHandler = new TransmissionHandler({sendingKey, receivingKey, chainingKey: this.chainingKey});

		return Buffer.concat([Buffer.alloc(1, 0), chacha, tag]);
	}

	public processActThree(actThreeMessage: Buffer) {
		this.assertRole(Role.RECEIVER);

		if (actThreeMessage.length != 66) {
			throw new Error('act one/two message must be 50 bytes');
		}
		const version = actThreeMessage.readUInt8(0);
		if (version !== 0) {
			throw new Error('unsupported version');
		}

		const chacha = actThreeMessage.slice(1, 50);
		const tag = actThreeMessage.slice(50, 66);

		const remotePublicKey = Handshake.decryptWithAD(this.temporaryKeys[1], BigInt(1), this.hash.value, chacha);
		this.remotePublicKey = Point.decodeFrom(secp256k1, remotePublicKey);

		this.hash.update(chacha);
		const sharedSecret = Handshake.ecdh({
			privateKey: this.ephemeralPrivateKey,
			publicKey: this.remotePublicKey
		});

		const derivative = Handshake.hkdf(this.chainingKey, sharedSecret);
		this.chainingKey = derivative.slice(0, 32);
		this.temporaryKeys[2] = derivative.slice(32);

		// make sure the tag checks out
		Handshake.decryptWithAD(this.temporaryKeys[2], BigInt(0), this.hash.value, tag);

		const transmissionKeys = Handshake.hkdf(this.chainingKey, Buffer.alloc(0));
		const receivingKey = transmissionKeys.slice(0, 32);
		const sendingKey = transmissionKeys.slice(32);

		this.txHandler = new TransmissionHandler({sendingKey, receivingKey, chainingKey: this.chainingKey});
	}

	private serializeActMessage({actIndex, ephemeralPrivateKey, peerPublicKey}: { actIndex: number, ephemeralPrivateKey: Bigi, peerPublicKey: Point }) {
		const ephemeralPublicKey = secp256k1.G.multiply(ephemeralPrivateKey);
		this.ephemeralPrivateKey = ephemeralPrivateKey;
		this.ephemeralPublicKey = ephemeralPublicKey;
		this.hash.update(this.ephemeralPublicKey.getEncoded(true));

		const sharedEphemeralSecret = Handshake.ecdh({
			privateKey: ephemeralPrivateKey,
			publicKey: peerPublicKey
		});

		const derivative = Handshake.hkdf(this.chainingKey, sharedEphemeralSecret);
		this.chainingKey = derivative.slice(0, 32);
		const temporaryKey = derivative.slice(32);
		this.temporaryKeys[actIndex] = temporaryKey;

		const chachaTag = Handshake.encryptWithAD(temporaryKey, BigInt(0), this.hash.value, Buffer.alloc(0));
		this.hash.update(chachaTag);

		return Buffer.concat([Buffer.alloc(1, 0), this.ephemeralPublicKey.getEncoded(true), chachaTag]);
	}

	private processActMessage({actIndex, message, localPrivateKey}: { actIndex: number, message: Buffer, localPrivateKey: Bigi }): Point {
		if (message.length != 50) {
			throw new Error('act one/two message must be 50 bytes');
		}
		const version = message.readUInt8(0);
		if (version !== 0) {
			throw new Error('unsupported version');
		}

		const ephemeralPublicKey = message.slice(1, 34);
		const chachaTag = message.slice(34, 50);

		const peerPublicKey = Point.decodeFrom(secp256k1, ephemeralPublicKey);
		this.hash.update(ephemeralPublicKey);

		const sharedEphemeralSecret = Handshake.ecdh({
			privateKey: localPrivateKey,
			publicKey: peerPublicKey
		});

		const derivative = Handshake.hkdf(this.chainingKey, sharedEphemeralSecret);
		this.chainingKey = derivative.slice(0, 32);
		const temporaryKey = derivative.slice(32);
		this.temporaryKeys[actIndex] = temporaryKey;

		Handshake.decryptWithAD(temporaryKey, BigInt(0), this.hash.value, chachaTag);
		this.hash.update(chachaTag);
		return peerPublicKey;
	}

	private static ecdh({privateKey, publicKey}: { privateKey: Bigi, publicKey: Point }) {
		const ephemeralSecretPreimage = publicKey.multiply(privateKey);
		const sharedSecret = crypto.createHash('sha256').update(ephemeralSecretPreimage.getEncoded(true)).digest();
		debug('Shared secret: %s', sharedSecret.toString('hex'));
		return sharedSecret;
	}

	public static hkdf(salt: Buffer, ikm: Buffer): Buffer {
		return HKDF.derive(salt, ikm);
	}

	/**
	 * Generate chacha stream
	 * @param key
	 * @param nonce
	 * @param associatedData
	 * @param plaintext
	 */
	public static encryptWithAD(key: Buffer, nonce: bigint, associatedData: Buffer, plaintext: Buffer): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);

		const cipher = chacha.createCipher(key, encodedNonce);
		cipher.setAAD(associatedData, {plaintextLength: plaintext.length});
		const output = cipher.update(plaintext);
		cipher.final();

		return Buffer.concat([output, cipher.getAuthTag()]);
	}

	/**
	 * Generate chacha stream
	 * @param key
	 * @param nonce
	 * @param associatedData
	 * @param ciphertext
	 */
	public static decryptWithAD(key: Buffer, nonce: bigint, associatedData: Buffer, ciphertext: Buffer): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);

		const rawCiphertext = ciphertext.slice(0, ciphertext.length - 16);
		const authenticationTag = ciphertext.slice(rawCiphertext.length);

		const cipher = chacha.createDecipher(key, encodedNonce);
		cipher.setAAD(associatedData, {plaintextLength: ciphertext.length - 16});
		cipher.setAuthTag(authenticationTag);

		// this should force the authentication
		const plaintext = cipher.update(rawCiphertext);
		cipher.final();

		return plaintext;
	}

}

export class HandshakeHash {

	private currentHash: Buffer;

	constructor(firstInput: Buffer | string) {
		this.currentHash = Buffer.alloc(0);
		this.update(firstInput);
	}

	get value(): Buffer {
		return this.currentHash;
	}

	public update(value: Buffer | string): Buffer {
		this.currentHash = crypto.createHash('sha256').update(this.currentHash).update(value).digest();
		return this.currentHash;
	}
}
