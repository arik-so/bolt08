import bigintBuffer = require('bigint-buffer');
import Bigi = require('bigi');
import chacha = require('chacha');
import debugModule = require('debug');
import ecurve = require('ecurve');
import * as crypto from 'crypto';
import hkdf from 'js-crypto-hkdf';
import {Point} from 'ecurve';

const debug = debugModule('bolt08:handshake');
const secp256k1 = ecurve.getCurveByName('secp256k1');

/**
 * Protocol for handling the key setup
 */
export default class Handshake {

	private privateKey: Bigi;
	private publicKey: Point;

	private remotePublicKey: Point;

	private hash: HandshakeHash;
	private chainKey: Buffer;

	constructor({privateKey = null}: { privateKey?: Buffer }) {
		if (!privateKey) {
			privateKey = crypto.randomBytes(32);
		}
		this.privateKey = Bigi.fromBuffer(privateKey);
		this.publicKey = secp256k1.G.multiply(this.privateKey);

		// initialize handshake hash
		const protocolName = Buffer.from('Noise_XK_secp256k1_ChaChaPoly_SHA256', 'ascii');
		this.chainKey = crypto.createHash('sha256').update(protocolName).digest();
		const prologue = Buffer.from('lightning', 'ascii');
		this.hash = new HandshakeHash(Buffer.concat([this.chainKey, prologue]));
	}

	public async serializeActOne({ephemeralPrivateKey = null, remotePublicKey}: { ephemeralPrivateKey?: Buffer, remotePublicKey: Buffer }): Promise<Buffer> {
		this.remotePublicKey = Point.decodeFrom(secp256k1, remotePublicKey);
		this.hash.update(this.remotePublicKey.getEncoded(true));

		if (!ephemeralPrivateKey) {
			ephemeralPrivateKey = crypto.randomBytes(32);
		}
		const ephemeralPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(ephemeralPrivateKey));
		this.hash.update(ephemeralPublicKey.getEncoded(true));

		const sharedEphemeralSecret = Handshake.ecdh({
			privateKey: ephemeralPrivateKey,
			publicKey: this.remotePublicKey
		});
		const derivative = await Handshake.hkdf(this.chainKey, sharedEphemeralSecret);
		debug('Act 1 key derivative: %s', derivative.toString('hex'));
		this.chainKey = derivative.slice(0, 32);
		const temporaryKey1 = derivative.slice(32);

		const chachaTag = Handshake.encryptWithAD(temporaryKey1, BigInt(0), this.hash.value, '');
		debug('Act 1 Chacha: %s', chachaTag.toString('hex'));
		this.hash.update(chachaTag);
		return Buffer.concat([Buffer.alloc(1, 0), ephemeralPublicKey.getEncoded(true), chachaTag]);
	}

	public async processActOne(actOneMessage: Buffer) {
		this.hash.update(this.publicKey.getEncoded(true));

		if (actOneMessage.length != 50) {
			throw new Error('act one message must be 50 bytes');
		}
		const version = actOneMessage.slice(0, 1);
		const ephemeralPublicKey = actOneMessage.slice(1, 34);
		const chachaTag = actOneMessage.slice(34, 50);

		this.hash.update(ephemeralPublicKey);

		const sharedEphemeralSecret = Handshake.ecdh({
			privateKey: this.privateKey.toBuffer(32),
			publicKey: ephemeralPublicKey
		});
		const derivative = await Handshake.hkdf(this.chainKey, sharedEphemeralSecret);
		this.chainKey = derivative.slice(0, 32);
		const temporaryKey1 = derivative.slice(32);

		Handshake.decryptWithAD(temporaryKey1, BigInt(0), this.hash.value, chachaTag);
		this.hash.update(chachaTag);
	}

	private static ecdh({privateKey, publicKey}: { privateKey: Buffer, publicKey: Point | Buffer }) {
		const privateKeyInteger = Bigi.fromBuffer(privateKey);

		let publicKeyPoint: Point;
		if (publicKey instanceof Point) {
			publicKeyPoint = publicKey;
		} else if (!(publicKey instanceof Point)) {
			publicKeyPoint = Point.decodeFrom(secp256k1, publicKey);
		}

		const ephemeralSecretPreimage = publicKeyPoint.multiply(privateKeyInteger);
		const sharedSecret = crypto.createHash('sha256').update(ephemeralSecretPreimage.getEncoded(true)).digest();
		debug('Shared secret: %s', sharedSecret.toString('hex'));
		return sharedSecret;
	}

	private static async hkdf(salt: Buffer, ikm: Buffer): Promise<Buffer> {
		const derivative = await hkdf.compute(ikm, 'SHA-256', 64, '', salt);
		return Buffer.from(derivative.key);
	}

	/**
	 * Generate chacha stream
	 * @param key
	 * @param nonce
	 * @param associatedData
	 * @param plaintext
	 */
	private static encryptWithAD(key: Buffer, nonce: bigint, associatedData: Buffer, plaintext: string): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);

		const cipher = chacha.createCipher(key, encodedNonce);
		cipher.setAAD(associatedData, {plaintextLength: plaintext.length});
		const output = cipher.update(plaintext);
		cipher.final();

		return Buffer.concat([cipher.getAuthTag(), output]);
	}

	/**
	 * Generate chacha stream
	 * @param key
	 * @param nonce
	 * @param associatedData
	 * @param ciphertext
	 */
	private static decryptWithAD(key: Buffer, nonce: bigint, associatedData: Buffer, ciphertext: Buffer): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);

		const cipher = chacha.createDecipher(key, encodedNonce);
		cipher.setAAD(associatedData, {plaintextLength: ciphertext.length - 16});
		cipher.setAuthTag(ciphertext);

		// this should force the authentication
		const plaintext = cipher.update(ciphertext.slice(16));
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
