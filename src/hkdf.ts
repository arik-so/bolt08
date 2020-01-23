import * as crypto from 'crypto';

export default class HKDF {

	static derive(salt: Buffer, master: Buffer) {
		const prk = crypto.createHmac('sha256', salt)
			.update(master)
			.digest();

		const t1 = crypto.createHmac('sha256', prk)
			.update(Buffer.from([1]))
			.digest();
		const t2 = crypto.createHmac('sha256', prk)
			.update(t1)
			.update(Buffer.from([2]))
			.digest();

		return Buffer.concat([t1, t2]);
	}
}
