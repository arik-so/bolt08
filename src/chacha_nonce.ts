import bigintBuffer = require('bigint-buffer');

export default class ChachaNonce {
	/**
	 * Generate chacha stream
	 * @param nonce
	 */
	public static encode(nonce: bigint): Buffer {
		const encodedNonce = Buffer.alloc(12, 0);
		// encode the nonce value as a little endian into the last 64 bits
		bigintBuffer.toBufferLE(nonce, 8).copy(encodedNonce, 4);
		return encodedNonce;
	}
}
