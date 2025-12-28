require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());
const port = 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;        
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const REDIRECT_URI = 'http://localhost:3000/callback';

console.log(`AUTH0_DOMAIN: ${AUTH0_DOMAIN}`);
console.log(`CLIENT_ID: ${AUTH0_CLIENT_ID}`);
console.log(`REDIRECT_URI: ${REDIRECT_URI}`);
console.log(`AUDIENCE: ${AUTH0_AUDIENCE || '(не вказано)'}`);

// JWKS клієнт для перевірки id_token
const client = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
    console.log(`Отримання підписуючого ключа для kid: ${header.kid}`);
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error('Помилка отримання ключа JWKS:', err.message);
            return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    console.log('\nЗапрос на головну сторінку (/):');

    const authHeader = req.get('Authorization');
    if (!authHeader) {
        console.log('Токен відсутній → віддаємо index.html з кнопкою Login');
        return res.sendFile(path.join(__dirname, 'index.html'));
    }

    const token = authHeader.split(' ')[1];
    console.log(`Отримано Bearer токен (початок): ${token.substring(0, 30)}...`);

    jwt.verify(token, getKey, {
        audience: AUTH0_CLIENT_ID,
        issuer: `https://${AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
    }, (err, decoded) => {
        if (err) {
            console.error('Помилка перевірки id_token:', err.message);
            if (err.name === 'TokenExpiredError') {
                console.error('Токен протермінований');
            }
            return res.sendFile(path.join(__dirname, 'index.html'));
        }

        console.log('id_token успішно перевірено!');
        console.log(`Користувач: ${decoded.name || decoded.email || decoded.sub}`);
        console.log(`sub: ${decoded.sub}`);
        console.log(`exp: ${new Date(decoded.exp * 1000).toLocaleString()}`);

        res.json({
            success: true,
            username: decoded.name || decoded.email || decoded.sub,
            logout: 'http://localhost:3000/logout'
        });
    });
});

app.get('/api/login', (req, res) => {
    console.log('\nКористувач натиснув Login → редірект на Auth0 (/api/login)');

    const state = crypto.randomBytes(16).toString('hex');
    console.log(`Згенеровано state (захист від CSRF): ${state}`);

    const authUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
    authUrl.searchParams.append('client_id', AUTH0_CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('response_mode', 'query');
    authUrl.searchParams.append('scope', 'openid profile email offline_access');
    authUrl.searchParams.append('state', state);

    if (AUTH0_AUDIENCE) {
        authUrl.searchParams.append('audience', AUTH0_AUDIENCE);
    }

    console.log('URL для Auth0:');
    console.log(authUrl.toString());

    res.cookie('auth_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 600000 });
    console.log('state збережено в cookie (auth_state)');

    console.log('Редіректимо користувача на сторінку логіну Auth0');
    res.redirect(authUrl.toString());
});

app.get('/callback', async (req, res) => {
    console.log('\nCallback від Auth0 (/callback)');
    console.log('Отримані параметри:', req.query);

    const { code, state } = req.query;

    if (!code) {
        console.error('Помилка: параметр code відсутній');
        return res.status(400).send('Missing authorization code');
    }

    if (state !== req.cookies.auth_state) {
        console.error('Помилка безпеки: невідповідність state!');
        console.error(`Очікуваний: ${req.cookies.auth_state}`);
        console.error(`Отриманий: ${state}`);
        return res.status(400).send('Invalid state parameter (CSRF protection)');
    }

    console.log('state перевірено успішно');
    res.clearCookie('auth_state');

    try {
        console.log('Обмін authorization code на токени...');

        const tokenResponse = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI
            }).toString(),
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            }
        );

        const { id_token, access_token, refresh_token, expires_in } = tokenResponse.data;

        console.log(`\n\nid_token: ${id_token}`);
        console.log(`\n\naccess_token: ${access_token}`);
        console.log(`\n\nrefresh_token: ${refresh_token}`);
        console.log(`\nexpires_in: ${expires_in}\n`);

        const redirectUrl = `/#id_token=${encodeURIComponent(id_token || '')}` +
                           `&access_token=${encodeURIComponent(access_token || '')}` +
                           `&refresh_token=${encodeURIComponent(refresh_token || '')}`;
        res.redirect(redirectUrl);

    } catch (err) {
        console.error('token exchange error');
        console.error('Код помилки:', err.response?.status);
        console.error('Помилка:', err.response?.data?.error || err.message);
        console.error('Опис:', err.response?.data?.error_description || '—');
        res.status(500).send('Authentication failed');
    }
});

app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/dbconnections/signup`,
            {
                client_id: AUTH0_CLIENT_ID,
                email: email,
                password: password,
                connection: 'Username-Password-Authentication'
            },
            {
                headers: { 'Content-Type': 'application/json' }
            }
        );

        console.log('new user created via /dbconnections/signup');
        console.log('Auth0 response:', response.data);

        res.json({
            success: true,
            message: 'user created'
        });
    } catch (err) {
        console.error('Помилка реєстрації (/dbconnections/signup):');
        console.error('Статус:', err.response?.status);
        console.error('Дані:', err.response?.data);

        let errorMsg = 'Реєстрація не вдалася';
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

app.get('/logout', (req, res) => {
    console.log('\logout => redirect to Auth0 logout');
    const logoutUrl = new URL(`https://${AUTH0_DOMAIN}/v2/logout`);
    logoutUrl.searchParams.append('client_id', AUTH0_CLIENT_ID);
    logoutUrl.searchParams.append('returnTo', 'http://localhost:3000');

    console.log('Redirect to:', logoutUrl.toString());
    res.redirect(logoutUrl.toString());
});

app.listen(port, () => {
    console.log(`http://localhost:${port}`);
    console.log(`Callback URL: ${REDIRECT_URI}`);
});