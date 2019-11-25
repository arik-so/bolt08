import bigintBuffer = require('bigint-buffer');
import chacha = require('chacha');
import * as crypto from 'crypto';
import hkdf from 'js-crypto-hkdf';

/**
 * Protocol for handling the key setup
 */
export default class Handshake {

	static async hkdf(salt: Buffer, ikm: Buffer): Promise<Buffer> {
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
	static encryptWithAD(key: Buffer, nonce: bigint, associatedData: Buffer, plaintext: string): Buffer {
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
