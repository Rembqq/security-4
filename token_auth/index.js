// server.js
require('dotenv').config();

const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const axios = require('axios'); // npm install axios

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
            console.log('Loaded sessions:', this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions, null, 2), 'utf-8');
    }

    set(key, value) {
        if (!value) value = {};
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId, {});
        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

/*
  Функції для Auth0
  Вимоги: задати в ENV:
    AUTH0_DOMAIN (наприклад: my-tenant.us.auth0.com)
    AUTH0_CLIENT_ID
    AUTH0_CLIENT_SECRET
    AUTH0_AUDIENCE  (якщо ви запитуєте API, наприклад https://my-api/)
    AUTH0_MGMT_CLIENT_ID (optional — якщо відрізняється)
    AUTH0_MGMT_CLIENT_SECRET (optional)
*/

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE; // optional, but typical for getting access tokens for your API

if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
    console.warn('Warning: AUTH0_DOMAIN, AUTH0_CLIENT_ID or AUTH0_CLIENT_SECRET not set. Auth0 functions will fail until these are provided.');
}

async function getManagementToken() {
    // client credentials grant to get Management API token
    const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
    const payload = {
        grant_type: 'client_credentials',
        client_id: process.env.AUTH0_MGMT_CLIENT_ID || AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_MGMT_CLIENT_SECRET || AUTH0_CLIENT_SECRET,
        audience: `https://${AUTH0_DOMAIN}/api/v2/`
    };

    const resp = await axios.post(tokenUrl, payload, {
        headers: { 'content-type': 'application/json' }
    });
    return resp.data.access_token;
}

async function createUser(email, password, connection = 'Username-Password-Authentication', name) {
    // Create user via Management API
    const mgmtToken = await getManagementToken();
    const url = `https://${AUTH0_DOMAIN}/api/v2/users`;
    const body = {
        connection,
        email,
        password,
        email_verified: false
    };
    if (name) body.name = name;

    const resp = await axios.post(url, body, {
        headers: {
            Authorization: `Bearer ${mgmtToken}`,
            'content-type': 'application/json'
        }
    });
    return resp.data;
}

async function authenticateUser(usernameOrEmail, password) {
    // Resource Owner Password Grant (ROP). Note: ROP must be enabled in Auth0 tenant for the client.
    const url = `https://${AUTH0_DOMAIN}/oauth/token`;
    const payload = {
        grant_type: 'password',
        username: usernameOrEmail,
        password: password,
        audience: AUTH0_AUDIENCE, // optional, include if you need access_token for an API
        scope: 'openid profile email offline_access', // offline_access -> refresh_token
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET
    };

    const resp = await axios.post(url, payload, { headers: { 'content-type': 'application/json' } });
    // resp.data typically contains: access_token, id_token, refresh_token (if offline_access granted), expires_in, token_type
    return resp.data;
}

async function refreshToken(refresh_token) {
    const url = `https://${AUTH0_DOMAIN}/oauth/token`;
    const payload = {
        grant_type: 'refresh_token',
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET,
        refresh_token
    };

    const resp = await axios.post(url, payload, { headers: { 'content-type': 'application/json' } });
    return resp.data; // new access_token (+ maybe id_token, expires_in)
}

async function checkRefreshToken(refresh_token) {
    try {
        const data = await refreshToken(refresh_token);
        return { valid: true, data };
    } catch (err) {
        return { valid: false, error: err.response?.data || err.message };
    }
}

/*
  Ендпоінти:
    POST /api/signup  { email, password, name? } -> створює користувача в Auth0 (Management API)
    POST /api/login   { username|login, password } -> логін через Auth0 (ROP), зберігає токени в сесії
    POST /api/refresh { refresh_token } -> оновити access token
    POST /api/check-refresh { refresh_token } -> перевірити refresh token
*/

app.post('/api/signup', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'email and password required' });
    }
    try {
        const user = await createUser(email, password, 'Username-Password-Authentication', name);
        // Optionally: save user in your local users array / DB
        res.status(201).json({ success: true, user });
    } catch (err) {
        console.error('createUser error:', err.response?.data || err.message);
        res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
});

app.post('/api/login', async (req, res) => {
    // Accept different field names from the form: username OR login OR email
    const usernameOrLogin = req.body.username || req.body.login || req.body.email;
    const password = req.body.password;
    if (!usernameOrLogin || !password) {
        return res.status(400).json({ error: 'username and password required' });
    }
    try {
        const tokens = await authenticateUser(usernameOrLogin, password);
        // Save minimal info in session
        req.session.username = usernameOrLogin;
        req.session.auth = tokens; // contains access_token, id_token, refresh_token (if any)
        return res.json({ token: req.sessionId, auth: tokens, username: usernameOrLogin });
    } catch (err) {
        console.error('authenticateUser error:', err.response?.data || err.message);
        return res.status(401).json({ error: err.response?.data || 'invalid credentials' });
    }
});

app.post('/api/refresh', async (req, res) => {
    let refresh_token = req.body.refresh_token;
    if (!refresh_token && req.session?.auth?.refresh_token) {
        // try to use session-stored refresh token
        refresh_token = req.session.auth.refresh_token;
    }
    if (!refresh_token) {
        return res.status(400).json({ error: 'refresh_token required' });
    }
    try {
        const newTokens = await refreshToken(refresh_token);
        // update session tokens if session used
        if (req.session) {
            req.session.auth = Object.assign({}, req.session.auth || {}, newTokens);
        }
        res.json({ success: true, tokens: newTokens });
    } catch (err) {
        console.error('refreshToken error:', err.response?.data || err.message);
        res.status(err.response?.status || 500).json({ error: err.response?.data || err.message });
    }
});


app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
