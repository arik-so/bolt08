export default class TransmissionHandler {
	public readonly sendingKey: Buffer;
	public readonly receivingKey: Buffer;


	constructor({sendingKey, receivingKey}: { sendingKey: Buffer, receivingKey: Buffer }) {
		this.sendingKey = sendingKey;
		this.receivingKey = receivingKey;
	}
}
