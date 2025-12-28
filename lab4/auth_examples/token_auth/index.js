require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;

const client = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

async function refreshAccessToken(refresh_token) {
    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                refresh_token: refresh_token
            }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const data = response.data;
        console.log('\nREFRESH');
        console.log('new access_token:', data.access_token);
        console.log('new refresh_token:', data.refresh_token || '(same)');
        console.log('expires_in:', data.expires_in);

        return {
            access_token: data.access_token,
            id_token: data.id_token,
            refresh_token: data.refresh_token || refresh_token,
            expires_in: data.expires_in
        };
    } catch (err) {
        console.error('Refresh failed:', err.response?.data || err.message);
        throw new Error('Failed to refresh token');
    }
}

app.get('/', (req, res) => {
    const authHeader = req.get('Authorization');
    if (!authHeader) {
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    const accessToken = parts[1];

    const decoded = jwt.decode(accessToken);
    if (!decoded || !decoded.exp) {
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    const expiresAt = decoded.exp * 1000; 
    const timeLeftMs = expiresAt - Date.now();

    if (timeLeftMs > 30_000) {
        jwt.verify(accessToken, getKey, {
            audience: AUTH0_CLIENT_ID,
            issuer: `https://${AUTH0_DOMAIN}/`,
            algorithms: ['RS256']
        }, (err, verified) => {
            if (err) {
                console.log('JWT verify error:', err.message);
                return res.sendFile(path.join(__dirname, 'index.html'));
            }

            return res.json({
                success: true,
                username: verified.name || verified.email || verified.sub,
                token: accessToken,          // повертаємо той самий токен
                refresh_token: req.refresh_token // якщо клієнт передавав, можна повернути
            });
        });
        return;
    }

    // Якщо залишилося <= 30 секунд — пробуємо оновити
    const refreshToken = req.get('X-Refresh-Token');

    if (!refreshToken) {
        console.log('No refresh token provided for renewal');
        return res.status(401).json({ error: 'Refresh token required for renewal' });
    }

    refreshAccessToken(refreshToken)
        .then(({ access_token, refresh_token }) => {
            jwt.verify(access_token, getKey, {
                audience: AUTH0_CLIENT_ID,
                issuer: `https://${AUTH0_DOMAIN}/`,
                algorithms: ['RS256']
            }, (err, verified) => {
                if (err) {
                    console.log('New token verification failed:', err.message);
                    return res.sendFile(path.join(__dirname, 'index.html'));
                }

                res.json({
                    success: true,
                    username: verified.name || verified.email || verified.sub,
                    token: access_token,       // новий токен
                    refresh_token: refresh_token
                });
            });
        })
        .catch(() => {
            res.status(401).json({ error: 'Token refresh failed' });
        });
});

app.get('/logout', (req, res) => {
    res.redirect('/');
});

app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
            client_id: AUTH0_CLIENT_ID,
            email,
            password,
            connection: 'Username-Password-Authentication'
        }, { headers: { 'Content-Type': 'application/json' } });

        res.json({ success: true });
    } catch (err) {
        console.error('Signup error:', err.response?.data || err.message);
        res.status(400).json({ error: err.response?.data?.description || 'Signup failed' });
    }
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: 'Login and password required' });
    }

    try {
        const response = await axios.post(
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

        const data = response.data;

        console.log('\nsuccessful login');
        console.log('access_token:', data.access_token || 'missed');
        console.log('refresh_token:', data.refresh_token || 'missed');
        console.log('expires_in:', data.expires_in);

        res.json({
            success: true,
            token: data.id_token || data.access_token,
            access_token: data.access_token,
            refresh_token: data.refresh_token,
            expires_in: data.expires_in
        });

    } catch (err) {
        console.error('Login error:', err.response?.data || err.message);
        const errorMsg = err.response?.data?.error_description || 'Invalid login or password';
        return res.status(401).json({ error: errorMsg });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});