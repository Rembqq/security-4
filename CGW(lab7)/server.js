const net = require('net');
const crypto = require('crypto');

function deriveKey(premaster, clientRandom, serverRandom, length) {
    const seed = Buffer.concat([clientRandom, serverRandom]);
    let key = Buffer.alloc(0);
    let data = Buffer.alloc(0);
    while (key.length < length) {
        data = crypto.createHmac('sha256', premaster).update(data).update(seed).digest();
        key = Buffer.concat([key, data]);
    }
    return key.slice(0, length);
}

const server = net.createServer((socket) => {
    console.log('New client connected:', socket.remoteAddress || 'localhost');

    // Generate server RSA key pair
    console.log('Generating server RSA key pair...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const exportedPublicKey = publicKey.export({ type: 'spki', format: 'pem' });
    console.log('Server public key generated\n');

    // Handshake state variables
    let clientRandom = null;
    let serverRandom = null;
    let premasterSecret = null;
    let sessionKey = null;
    let handshakeCompleted = false;

    let buffer = Buffer.alloc(0);

    socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        let parts = buffer.toString().split('\n');
        const lastPart = parts.pop();
        if (lastPart) buffer = Buffer.from(lastPart);
        else buffer = Buffer.alloc(0);

        for (let message of parts) {
            message = message.trim();
            if (!message) continue;

            // Step 1: Client Hello
            if (!clientRandom && message.startsWith('CLIENT_HELLO:')) {
                clientRandom = Buffer.from(message.split(':')[1], 'hex');
                console.log('[Step 1] Received Client Hello');
                console.log('Client Random:', clientRandom.toString('hex'));

                serverRandom = crypto.randomBytes(32);
                console.log('Generated Server Random:', serverRandom.toString('hex'));

                const serverHello = {
                    type: 'SERVER_HELLO',
                    serverRandom: serverRandom.toString('hex'),
                    publicKey: exportedPublicKey
                };
                socket.write(JSON.stringify(serverHello) + '\n');
                console.log('Sent Server Hello with public key\n');
                continue;
            }

            // Step 4: Encrypted premaster secret
            if (clientRandom && !premasterSecret && !message.startsWith('{')) {
                try {
                    const encryptedPremaster = Buffer.from(message, 'base64');
                    console.log('[Step 4] Received encrypted premaster secret');
                    console.log('Ciphertext (base64, first 64 chars):', message.slice(0, 64) + '...');

                    premasterSecret = crypto.privateDecrypt(privateKey, encryptedPremaster);
                    console.log('Successfully decrypted premaster secret:', premasterSecret.toString('hex'));

                    // Step 5: Derive session key
                    sessionKey = deriveKey(premasterSecret, clientRandom, serverRandom, 32);
                    console.log('[Step 5] Derived Session Key (AES-256-GCM):');
                    console.log('Key (hex):', sessionKey.toString('hex'));

                    // Step 6: Send SERVER_FINISHED
                    const iv = crypto.randomBytes(12);
                    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
                    const encryptedFinished = Buffer.concat([cipher.update('SERVER_FINISHED', 'utf8'), cipher.final()]);
                    const tag = cipher.getAuthTag();

                    const finishedMsg = {
                        type: 'FINISHED',
                        iv: iv.toString('base64'),
                        tag: tag.toString('base64'),
                        data: encryptedFinished.toString('base64')
                    };

                    socket.write(JSON.stringify(finishedMsg) + '\n');
                    console.log('Sent encrypted SERVER_FINISHED');
                    console.log('IV:', iv.toString('hex'));
                    console.log('Auth Tag:', tag.toString('hex') + '\n');

                    handshakeCompleted = true;
                } catch (e) {
                    console.error('Error decrypting premaster secret:', e.message);
                }
                continue;
            }

            // After handshake: process JSON messages
            if (handshakeCompleted && message.startsWith('{')) {
                try {
                    const msg = JSON.parse(message);

                    if (msg.type === 'FINISHED') {
                        console.log('Received CLIENT_FINISHED - handshake fully completed!\n');
                    }

                    if (msg.type === 'ENCRYPTED_MESSAGE') {
                        const iv = Buffer.from(msg.iv, 'base64');
                        const tag = Buffer.from(msg.tag, 'base64');
                        const ciphertext = Buffer.from(msg.data, 'base64');

                        console.log('Received encrypted message from client');
                        console.log('IV:', iv.toString('hex'));

                        const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
                        decipher.setAuthTag(tag);
                        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

                        console.log('Decrypted: "' + decrypted.toString() + '"\n');

                        // Send response
                        const responseText = 'Hello from server, secure channel works.';
                        const respIv = crypto.randomBytes(12);
                        const respCipher = crypto.createCipheriv('aes-256-gcm', sessionKey, respIv);
                        const encResp = Buffer.concat([respCipher.update(responseText, 'utf8'), respCipher.final()]);
                        const respTag = respCipher.getAuthTag();

                        socket.write(JSON.stringify({
                            type: 'ENCRYPTED_MESSAGE',
                            iv: respIv.toString('base64'),
                            tag: respTag.toString('base64'),
                            data: encResp.toString('base64')
                        }) + '\n');

                        console.log('Sent encrypted response to client\n');
                    }
                } catch (e) {
                    console.error('Error processing JSON message:', e.message);
                }
            }
        }
    });

    socket.on('close', () => {
        console.log('Client disconnected\n');
    });
});

server.listen(3000, () => {
    console.log('TLS imitation server running on port 3000\n');
});