require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { createPublicKey, createPrivateKey } = require('crypto');
const jose = require('jose'); 

const app = express();
const port = 3000;

// налаштування Auth0 
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;

if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET || !AUTH0_AUDIENCE) {
    console.error('missing env var');
    process.exit(1);
}

const PUBLIC_PEM = fs.readFileSync(path.join(__dirname, 'rsa.pem.pub'), 'utf8');
const PRIVATE_PEM = fs.readFileSync(path.join(__dirname, 'rsa.pem'), 'utf8');

const publicKey = createPublicKey(PUBLIC_PEM);   
const privateKey = createPrivateKey(PRIVATE_PEM);

let publicJWK = null;

async function initJose() {
    if (publicJWK) return publicJWK;
    const jose = await import('jose');
    publicJWK = await jose.importSPKI(PUBLIC_PEM, 'RSA-OAEP-256');
    return publicJWK;
}

async function encryptPayload(payloadObj) {
    const jwk = await initJose();  
    const jwe = await new jose.CompactEncrypt(
        new TextEncoder().encode(JSON.stringify(payloadObj))
    )
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
        .encrypt(jwk);
    return jwe;
}

async function decryptPayload(jweString) {
    try {
        const jose = await import('jose');
        const { plaintext } = await jose.compactDecrypt(jweString, privateKey);
        return JSON.parse(new TextDecoder().decode(plaintext));
    } catch (err) {
        console.error('JWE дешифрування не вдалося:', err.message);
        return null;
    }
}

// Middleware 
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// перевірка JWT через rsa.pem.pub 
app.get('/', (req, res) => {
    const authHeader = req.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, publicKey, {
        audience: AUTH0_AUDIENCE,
        issuer: `https://${AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.log('JWT failed:', err.message);
            return res.sendFile(path.join(__dirname, 'index.html'));
        }
        console.log('JWT підпис перевірено локальним публічним ключем. Користувач:', decoded.sub);
        res.json({
            success: true,
            username: decoded.name || decoded.email || decoded.sub,
            logout: '/logout'
        });
    });
});

app.get('/logout', (req, res) => res.redirect('/'));


app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
            client_id: AUTH0_CLIENT_ID,
            email,
            password,
            connection: 'Username-Password-Authentication'
        }, { headers: { 'Content-Type': 'application/json' } });

        
        console.log('Користувач успішно створений в Auth0:', response.data);

        res.json({ 
            success: true,
            message: 'Користувач створений. Якщо потрібна верифікація — перевірте email.'
        });
    } catch (err) {
        console.error('Signup error:', err.response?.status, err.response?.data);

        let errorMsg = 'Реєстрація провалилась';
        if (err.response?.data) {
            errorMsg = err.response.data.description || 
                       err.response.data.message || 
                       err.response.data.error || 
                       JSON.stringify(err.response.data);
        }

        res.status(400).json({ 
            error: errorMsg,
            details: err.response?.data  
        });
    }
});


app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'Login and password required' });

    try {
        const { data } = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'password',
                username: login,
                password: password,
                audience: AUTH0_AUDIENCE,
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                scope: 'openid profile email offline_access'
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        
        const payloadBase64 = data.access_token.split('.')[1];
        const payloadObj = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString());

        
        const encryptedPayload = await encryptPayload(payloadObj);

        console.log('\n=== Логін успішний ===');
        console.log('Payload зашифровано у JWE (RSA-OAEP-256 + A256GCM)');
        console.log('JWE токен:', encryptedPayload);
        console.log('========================\n');

        res.json({
            token: data.access_token,            // jwt
            refresh_token: data.refresh_token,
            expires_in: data.expires_in,
            encrypted_payload: encryptedPayload  // зашифрований payload 
        });

    } catch (err) {
        console.error('Login error:', err.response?.data || err.message);
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

    try {
        const { data } = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                refresh_token
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        res.json({
            token: data.access_token,
            refresh_token: data.refresh_token || refresh_token,
            expires_in: data.expires_in
        });
    } catch (err) {
        console.error('Refresh error:', err.response?.data || err.message);
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/api/decrypt', async (req, res) => {
    const { encrypted_payload } = req.body;
    if (!encrypted_payload) return res.status(400).json({ error: 'encrypted_payload required' });

    const decrypted = await decryptPayload(encrypted_payload);
    if (!decrypted) return res.status(400).json({ error: 'Не вдалося розшифрувати JWE' });

    res.json({ decrypted_payload: decrypted });
});

app.listen(port, () => {
    console.log(`\nСервер запущено: http://localhost:${port}`);
    console.log(`JWT check local rsa.pem.pub (RS256)`);
    console.log(`rsa.pem + rsa.pem.pub`);
});