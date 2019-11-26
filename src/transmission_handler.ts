import Handshake from './handshake';

export default class TransmissionHandler {
	private sendingKey: Buffer;
	private receivingKey: Buffer;
	private chainingKey: Buffer;

	private sendingNonce: number = 0;
	private receivingNonce: number = 0;

	constructor({sendingKey, receivingKey, chainingKey}: { sendingKey: Buffer, receivingKey: Buffer, chainingKey: Buffer }) {
		this.sendingKey = sendingKey;
		this.receivingKey = receivingKey;
		this.chainingKey = chainingKey;
	}

	public send(message: Buffer): Buffer {
		const length = message.length;

		const lengthBuffer = Buffer.alloc(2);
		lengthBuffer.writeUInt16BE(length, 0);

		const encryptedLength = Handshake.encryptWithAD(this.sendingKey, BigInt(this.sendingNonce), Buffer.alloc(0), lengthBuffer);
		this.incrementSendingNonce();

		const encryptedMessage = Handshake.encryptWithAD(this.sendingKey, BigInt(this.sendingNonce), Buffer.alloc(0), message);
		this.incrementSendingNonce();

		return Buffer.concat([encryptedLength, encryptedMessage]);
	}

	public receive(undelimitedBuffer: Buffer): Buffer {
		const encryptedLength = undelimitedBuffer.slice(0, 18);
		const lengthBuffer = Handshake.decryptWithAD(this.receivingKey, BigInt(this.receivingNonce), Buffer.alloc(0), encryptedLength);
		const length = lengthBuffer.readUInt16BE(0);

		this.incrementReceivingNonce();

		const encryptedMessage = undelimitedBuffer.slice(18, 18 + length + 16);
		const message = Handshake.decryptWithAD(this.receivingKey, BigInt(this.receivingNonce), Buffer.alloc(0), encryptedMessage);

		this.incrementReceivingNonce();

		return message;
	}

	private incrementSendingNonce() {
		this.sendingNonce++;
		if (this.sendingNonce >= 1000) {
			this.sendingKey = this.rotateKey(this.sendingKey);
			this.sendingNonce = 0;
		}
	}

	private incrementReceivingNonce() {
		this.receivingNonce++;
		if (this.receivingNonce >= 1000) {
			this.receivingKey = this.rotateKey(this.receivingKey);
			this.receivingNonce = 0;
		}
	}

	private rotateKey(key: Buffer): Buffer {
		const derivative = Handshake.hkdf(this.chainingKey, key);
		this.chainingKey = derivative.slice(0, 32);
		return derivative.slice(32);
	}
}
