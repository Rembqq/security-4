// server.js
require('dotenv').config();

const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = process.env.PORT || 3000;
const fs = require('fs');
const axios = require('axios');

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
            logout: 'http://localhost:' + port + '/logout'
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

/*
  Auth0 config (env):
    AUTH0_DOMAIN (e.g. my-tenant.us.auth0.com)
    AUTH0_CLIENT_ID
    AUTH0_CLIENT_SECRET
    AUTH0_AUDIENCE (optional)
    AUTH0_MGMT_CLIENT_ID (optional, recommended — client created for Management API)
    AUTH0_MGMT_CLIENT_SECRET (optional)
*/

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;


if (!AUTH0_DOMAIN || !AUTH0_CLIENT_ID || !AUTH0_CLIENT_SECRET) {
    console.warn('Warning: AUTH0_DOMAIN, AUTH0_CLIENT_ID or AUTH0_CLIENT_SECRET not set. Auth0 functions will fail until these are provided.');
}

// get Management API token (client credentials)
async function getManagementToken() {
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

async function sendVerificationEmail(user_id) {
    // Triggers Auth0 verification email job
    const mgmtToken = await getManagementToken();
    const url = `https://${AUTH0_DOMAIN}/api/v2/jobs/verification-email`;
    const body = { user_id }; // client_id optional
    const resp = await axios.post(url, body, {
        headers: {
            Authorization: `Bearer ${mgmtToken}`,
            'content-type': 'application/json'
        }
    });
    return resp.data;
}

async function authenticateUser(usernameOrEmail, password) {
    const url = `https://${AUTH0_DOMAIN}/oauth/token`;
    const payload = {
        grant_type: 'password',
        username: usernameOrEmail,
        password: password,
        audience: AUTH0_AUDIENCE,
        scope: 'openid profile email offline_access',
        client_id: AUTH0_CLIENT_ID,
        client_secret: AUTH0_CLIENT_SECRET
    };

    const resp = await axios.post(url, payload, { headers: { 'content-type': 'application/json' } });
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
    return resp.data;
}

async function checkRefreshToken(refresh_token) {
    try {
        const data = await refreshToken(refresh_token);
        return { valid: true, data };
    } catch (err) {
        return { valid: false, error: err.response?.data || err.message };
    }
}

// Utility: normalize error message to string for frontend
function extractErrorMessage(err) {
    if (!err) return 'unknown error';
    if (err.response && err.response.data) {
        const d = err.response.data;
        // Auth0 often returns {statusCode, error, message} or an object; try to extract meaningful text
        if (typeof d === 'string') return d;
        if (d.message) return d.message;
        if (d.error_description) return d.error_description;
        if (d.error) {
            if (typeof d.error === 'string') return d.error;
            // sometimes error is an object
            return JSON.stringify(d.error);
        }
        // fallback to JSON string
        try { return JSON.stringify(d); } catch(e) { return String(d); }
    }
    return err.message || String(err);
}

/*
  Endpoints:
    POST /api/signup  { email, password, name? } -> create user + send verification email
    POST /api/login   { username|login|email, password } -> ROP login, store tokens in session
    POST /api/refresh { refresh_token } -> refresh access token
*/

app.post('/api/signup', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'email and password required' });
    }
    try {
        // create user in Auth0
        const user = await createUser(email, password, 'Username-Password-Authentication', name);
        // Trigger verification email (requires that you have an email provider set up in Auth0 dashboard)
        let emailJob = null;
        try {
            emailJob = await sendVerificationEmail(user.user_id || user.user_id);
        } catch (jobErr) {
            console.warn('Failed to start verification email job:', extractErrorMessage(jobErr));
            // keep going — user was created, but email job failed
        }

        res.status(201).json({ success: true, user, emailJob });
    } catch (err) {
        console.error('createUser error:', err.response?.data || err.message);
        const message = extractErrorMessage(err);
        // choose status code if available
        const status = err.response?.status || 500;
        res.status(status).json({ error: message });
    }
});

app.post('/api/login', async (req, res) => {
    const usernameOrLogin = req.body.username || req.body.login || req.body.email;
    const password = req.body.password;
    if (!usernameOrLogin || !password) {
        return res.status(400).json({ error: 'username and password required' });
    }
    try {
        const tokens = await authenticateUser(usernameOrLogin, password);
        req.session.username = usernameOrLogin;
        req.session.auth = tokens;
        return res.json({ token: req.sessionId, auth: tokens, username: usernameOrLogin });
    } catch (err) {
        console.error('authenticateUser error:', err.response?.data || err.message);
        const message = extractErrorMessage(err);
        return res.status(401).json({ error: message });
    }
});

app.post('/api/refresh', async (req, res) => {
    let refresh_token = req.body.refresh_token;
    if (!refresh_token && req.session?.auth?.refresh_token) {
        refresh_token = req.session.auth.refresh_token;
    }
    if (!refresh_token) {
        return res.status(400).json({ error: 'refresh_token required' });
    }
    try {
        const newTokens = await refreshToken(refresh_token);
        if (req.session) {
            req.session.auth = Object.assign({}, req.session.auth || {}, newTokens);
        }
        res.json({ success: true, tokens: newTokens });
    } catch (err) {
        console.error('refreshToken error:', err.response?.data || err.message);
        const message = extractErrorMessage(err);
        res.status(err.response?.status || 500).json({ error: message });
    }
});


app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
