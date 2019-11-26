import chai = require('chai');
import TransmissionHandler from '../src/transmission_handler';

const assert = chai.assert;

describe('Transmission Handler Tests', () => {

	it('should simulate a transmission', async () => {
		const chainingKey = Buffer.from('919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01', 'hex');
		const sendingKey = Buffer.from('969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9', 'hex');
		const receivingKey = Buffer.from('bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442', 'hex');
		const txHandler = new TransmissionHandler({chainingKey, sendingKey, receivingKey});

		const message = Buffer.from('68656c6c6f', 'hex');
		const messageBuffers: Buffer[] = [];

		for (let i = 0; i < 1002; i++) {
			messageBuffers[i] = await txHandler.send(message);
		}

		assert.equal(messageBuffers[0].toString('hex'), 'cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95');
		assert.equal(messageBuffers[1].toString('hex'), '72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1');
		assert.equal(messageBuffers[500].toString('hex'), '178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8');
		assert.equal(messageBuffers[501].toString('hex'), '1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd');
		assert.equal(messageBuffers[1000].toString('hex'), '4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09');
		assert.equal(messageBuffers[1001].toString('hex'), '2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36');
	});

});
