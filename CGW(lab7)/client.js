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

const client = net.createConnection({ port: 3000 }, () => {
    console.log('Connected to server\n');

    // Step 1: Generate and save clientRandom
    clientRandom = crypto.randomBytes(32);
    console.log('[Step 1] Generated Client Random:', clientRandom.toString('hex'));
    client.write(`CLIENT_HELLO:${clientRandom.toString('hex')}\n`);
    console.log('Sent Client Hello\n');
});

// Global variables
let clientRandom;
let serverRandom;
let serverPublicKey;
let premasterSecret;
let sessionKey;

client.on('data', (data) => {
    const messages = data.toString().split('\n').filter(m => m.trim());

    for (const message of messages) {
        if (message.startsWith('{')) {
            try {
                const parsed = JSON.parse(message);

                // Step 2: Server Hello
                if (parsed.type === 'SERVER_HELLO') {
                    serverRandom = Buffer.from(parsed.serverRandom, 'hex');
                    serverPublicKey = crypto.createPublicKey(parsed.publicKey);

                    console.log('[Step 2] Received Server Hello');
                    console.log('Server Random:', serverRandom.toString('hex'));
                    console.log('Server Public Key received\n');

                    // Step 3-4: Premaster secret
                    premasterSecret = crypto.randomBytes(48);
                    console.log('[Step 3] Generated Premaster Secret:', premasterSecret.toString('hex'));

                    const encryptedPremaster = crypto.publicEncrypt(serverPublicKey, premasterSecret);
                    console.log('Premaster encrypted with server public key');
                    console.log('Ciphertext (base64, first 64 chars):', encryptedPremaster.toString('base64').slice(0, 64) + '...');

                    client.write(encryptedPremaster.toString('base64') + '\n');
                    console.log('Sent encrypted premaster secret\n');

                    // Step 5: Session key derivation
                    sessionKey = deriveKey(premasterSecret, clientRandom, serverRandom, 32);
                    console.log('[Step 5] Derived Session Key (AES-256-GCM):');
                    console.log('Key (hex):', sessionKey.toString('hex') + '\n');
                }

                // Step 6: SERVER_FINISHED
                if (parsed.type === 'FINISHED') {
                    const iv = Buffer.from(parsed.iv, 'base64');
                    const tag = Buffer.from(parsed.tag, 'base64');
                    const ciphertext = Buffer.from(parsed.data, 'base64');

                    console.log('[Step 6] Received encrypted SERVER_FINISHED');
                    console.log('IV:', iv.toString('hex'));

                    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
                    decipher.setAuthTag(tag);
                    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

                    console.log('Decrypted message: "' + decrypted.toString() + '"');

                    if (decrypted.toString() === 'SERVER_FINISHED') {
                        console.log('TLS Handshake successfully completed!\n');

                        // Send CLIENT_FINISHED
                        const clientIv = crypto.randomBytes(12);
                        const clientCipher = crypto.createCipheriv('aes-256-gcm', sessionKey, clientIv);
                        const encFinished = Buffer.concat([clientCipher.update('CLIENT_FINISHED', 'utf8'), clientCipher.final()]);
                        const clientTag = clientCipher.getAuthTag();

                        client.write(JSON.stringify({
                            type: 'FINISHED',
                            iv: clientIv.toString('base64'),
                            tag: clientTag.toString('base64'),
                            data: encFinished.toString('base64')
                        }) + '\n');

                        // Send test encrypted message after a short delay
                        setTimeout(() => {
                            const text = 'Hello server, from secure channel after a handshake';
                            const msgIv = crypto.randomBytes(12);
                            const msgCipher = crypto.createCipheriv('aes-256-gcm', sessionKey, msgIv);
                            const encMsg = Buffer.concat([msgCipher.update(text, 'utf8'), msgCipher.final()]);
                            const msgTag = msgCipher.getAuthTag();

                            console.log('\nSending encrypted application message:');
                            console.log('Plaintext:', text);

                            client.write(JSON.stringify({
                                type: 'ENCRYPTED_MESSAGE',
                                iv: msgIv.toString('base64'),
                                tag: msgTag.toString('base64'),
                                data: encMsg.toString('base64')
                            }) + '\n');
                        }, 500);
                    }
                }

                // Encrypted messages from server
                if (parsed.Hello, type === 'ENCRYPTED_MESSAGE') {
                    const iv = Buffer.from(parsed.iv, 'base64');
                    const tag = Buffer.from(parsed.tag, 'base64');
                    const ciphertext = Buffer.from(parsed.data, 'base64');

                    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
                    decipher.setAuthTag(tag);
                    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

                    console.log('\nReceived encrypted message from server:');
                    console.log('Decrypted: "' + decrypted.toString() + '"\n');
                }
            } catch (e) {
                console.error('JSON parsing error:', e.message);
            }
        }
    }
});

client.on('close', () => console.log('Connection closed'));
client.on('error', (err) => console.error('Client error:', err.message));