import * as crypto from 'crypto';

export default class HKDF {

	private static readonly HASH_LENGTH = 32;

	static derive(salt: Buffer, master: Buffer, length: number = 64, info: string = ''): Buffer {
		// RFC5869 Step 1 (Extract)
		const prk = crypto.createHmac('sha256', salt).update(master).digest();

		const hashLength = this.HASH_LENGTH;

		// RFC5869 Step 2 (Expand)
		let t = new Uint8Array([]);
		const okm = new Uint8Array(Math.ceil(length / hashLength) * hashLength);
		const uintInfo = Buffer.from(info, 'ascii');
		for (let i = 0; i < Math.ceil(length / hashLength); i++) {
			const concat = new Uint8Array(t.length + uintInfo.length + 1);
			concat.set(t);
			concat.set(uintInfo, t.length);
			concat.set(new Uint8Array([i + 1]), t.length + uintInfo.length);
			t = crypto.createHmac('sha256', prk).update(concat).digest();
			okm.set(t, hashLength * i);
		}
		return Buffer.from(okm.slice(0, length));
	}
}
