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

	private remotePublicKey: Buffer;

	private hash: HandshakeHash;
	private chainKey: Buffer;

	constructor({privateKey = null, remotePublicKey}: { privateKey?: Buffer, remotePublicKey: Buffer }) {
		if (!privateKey) {
			privateKey = crypto.randomBytes(32);
		}
		this.privateKey = Bigi.fromBuffer(privateKey);
		this.publicKey = secp256k1.G.multiply(this.privateKey);
		this.remotePublicKey = remotePublicKey;
	}

	public async serializeActOne({ephemeralPrivateKey = null}: { ephemeralPrivateKey?: Buffer }): Promise<Buffer> {
		// initialize handshake hash
		const protocolName = Buffer.from('Noise_XK_secp256k1_ChaChaPoly_SHA256', 'ascii');
		this.chainKey = crypto.createHash('sha256').update(protocolName).digest();
		const prologue = Buffer.from('lightning', 'ascii');
		this.hash = new HandshakeHash(Buffer.concat([this.chainKey, prologue]));
		this.hash.update(this.remotePublicKey);

		if (!ephemeralPrivateKey) {
			ephemeralPrivateKey = crypto.randomBytes(32);
		}
		const ephemeralPublicKey = secp256k1.G.multiply(Bigi.fromBuffer(ephemeralPrivateKey));
		this.hash.update(ephemeralPublicKey.getEncoded(true));

		const ephemeralSecret = Handshake.ecdh({privateKey: ephemeralPrivateKey, publicKey: this.remotePublicKey});
		const derivative = await Handshake.hkdf(this.chainKey, ephemeralSecret);
		debug('Act 1 key derivative: %s', derivative.toString('hex'));
		this.chainKey = derivative.slice(0, 32);
		const temporaryKey1 = derivative.slice(32);

		const chachaStream = Handshake.encryptWithAD(temporaryKey1, BigInt(0), this.hash.value, '');
		debug('Act 1 Chacha: %s', chachaStream.toString('hex'));
		this.hash.update(chachaStream);
		return Buffer.concat([Buffer.alloc(1, 0), ephemeralPublicKey.getEncoded(true), chachaStream]);
	}

	public async processActOne() {

	}

	private static ecdh({privateKey, publicKey}: { privateKey: Buffer, publicKey: Buffer }) {
		const publicKeyPoint = Point.decodeFrom(secp256k1, publicKey);
		const privateKeyInteger = Bigi.fromBuffer(privateKey);
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
		cipher.setAAD(associatedData, {plaintextLength: 0});
		cipher.final();

		return cipher.getAuthTag();
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
