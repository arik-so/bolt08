import Handshake from '../src/handshake';
import * as crypto from 'crypto';

describe('Readme Example Tests', () => {

	xit('should add a peer', () => {

		// we initialize a new node instance with a local private key
		const privateKey = crypto.randomBytes(32);
		const handshakeHandler = new Handshake({privateKey});

		// we know the counterparty's public key, so we initiate the connection
		const remotePublicKey = Buffer.from('028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7', 'hex');
		const actOne = handshakeHandler.serializeActOne({remotePublicKey});

		// we send act one to the remote party, and receive their act two response
		// we do not go into detail for how the transmission is facilitated through TCP
		// @ts-ignore
		const incomingActTwo: Buffer = oracle.sendAndReceive(actOne);
		handshakeHandler.processActTwo(incomingActTwo);

		// now we perform the final act
		const actThree = handshakeHandler.serializeActThree();
		// @ts-ignore
		oracle.send(actThree); // we do not care about the response

		// having performed act three, we can now send messages back and forth
		const transmissionHandler = handshakeHandler.transmissionHandler;

		const message = Buffer.from('Hello World!', 'ascii');
		const serializedMessage = transmissionHandler.send(message); // serializedMessage is what we send over TCP
	});

	xit('should respond to a handshake', () => {
		// we initialize a new node instance with a local private key
		const privateKey = crypto.randomBytes(32);
		const handshakeHandler = new Handshake({privateKey});

		// @ts-ignore
		const incomingActOne: Buffer = oracle.receive();
		handshakeHandler.processActOne(incomingActOne);

		const actTwo = handshakeHandler.serializeActTwo({});
		// @ts-ignore
		const incomingActThree = oracle.sendAndReceive(actTwo);

		handshakeHandler.processActThree(incomingActThree);

		// having processed act three, we can now send messages back and forth
		const transmissionHandler = handshakeHandler.transmissionHandler;

		const message = Buffer.from('Welcome!', 'ascii');
		const serializedMessage = transmissionHandler.send(message); // serializedMessage is what we send over TCP
	});

});
