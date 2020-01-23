import * as crypto from 'crypto';

export default class HKDF {

	static derive(salt: Buffer, master: Buffer) {
		const key = crypto.createHmac('sha256', salt)
			.update(master)
			.digest();

		const part1 = crypto.createHmac('sha256', key)
			.update(Buffer.from([1]))
			.digest();
		const part2 = crypto.createHmac('sha256', key)
			.update(part1)
			.update(Buffer.from([2]))
			.digest();

		return Buffer.concat([part1, part2]);
	}
}
