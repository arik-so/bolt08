import bigintBuffer = require('bigint-buffer');
import chacha = require('chacha-native');
import debugModule = require('debug');

const debug = debugModule('bolt08:chacha');

export default class Chacha {
	/**
	 * Generate chacha stream
	 * @param key
	 * @param nonce
	 * @param associatedData
	 * @param plaintext
	 */
	public static encrypt(key: Buffer, nonce: bigint, associatedData: Buffer, plaintext: Buffer): Buffer {
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
	 * @param taggedCiphertext
	 */
	public static decrypt(key: Buffer, nonce: bigint, associatedData: Buffer, taggedCiphertext: Buffer): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);

		const rawCiphertext = taggedCiphertext.slice(0, taggedCiphertext.length - 16);
		const authenticationTag = taggedCiphertext.slice(rawCiphertext.length);

		const cipher = chacha.createDecipher(key, encodedNonce);
		cipher.setAAD(associatedData, {plaintextLength: taggedCiphertext.length - 16});
		cipher.setAuthTag(authenticationTag);

		// this should force the authentication
		const plaintext = cipher.update(rawCiphertext);
		try {
			cipher.final();
			debug('Decryption success');
			debug('Nonce: %d', Number(nonce));
			debug('Tagged ciphertext: %s', taggedCiphertext.toString('hex'));
		} catch (e) {
			debug('Decryption failure');
			debug('Key: %s', key.toString('hex'));
			debug('Nonce: %d', Number(nonce));
			debug('Associated data: %s', associatedData.toString('hex'));
			debug('Tagged ciphertext: %s', taggedCiphertext.toString('hex'));
			throw e;
		}

		return plaintext;
	}
}
