const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000; // Render provides the PORT environment variable

// Simple in-memory store for state values (in production, use Redis or database)
const stateStore = new Map();

// --- Accessing your Environment Variables ---
const APP_URL = process.env.APP_URL; // This should be 'https://seo.daveenci.ai'
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL; // Base auth server URL
const DATABASE_URL = process.env.DATABASE_URL; // Might not be directly used in this simple test app
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
// The OAUTH_REDIRECT_URI *must* match the URL where your auth server will redirect back to this app.
// For Render, this will be your custom domain + path, e.g., 'https://seo.daveenci.ai/auth/callback'
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET; // Used for session management, if you implement it

// OAuth Endpoint URLs (can be full URLs or will be constructed from AUTH_SERVER_URL + paths)
// OAUTH_AUTHORIZE_URL, OAUTH_TOKEN_URL, OAUTH_USERINFO_URL

// OAuth Configuration
const OAUTH_SCOPES = process.env.OAUTH_SCOPES || 'openid profile email';

// --- Basic Routes for Testing ---

// Handle favicon requests to prevent 404 errors in logs
app.get('/favicon.ico', (req, res) => {
    res.status(204).send(); // No content response
});

// 1. Home Page: Provides a link to initiate the login flow
app.get('/', (req, res) => {
    res.send(`
        <h1>Welcome to the Auth Test App (${APP_URL})!</h1>
        <p>This application is designed to test your authentication server.</p>
        <p>Your configured Auth Server: <code>${AUTH_SERVER_URL}</code></p>
        <p>Your Client ID: <code>${OAUTH_CLIENT_ID}</code></p>
        <p>Your Redirect URI: <code>${OAUTH_REDIRECT_URI}</code></p>
        <p>Your OAuth Scopes: <code>${OAUTH_SCOPES}</code></p>
        <hr>
        <p><strong>✅ Configuration Status:</strong></p>
        <div style="background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0;">
            <p><strong>Based on your OAuth server config:</strong></p>
            <ul>
                <li><strong>Redirect URI:</strong> <code>https://seo.daveenci.ai/auth/callback</code> ✅ Configured</li>
                <li><strong>Allowed Scopes:</strong> <code>openid profile email</code> ✅ Match default</li>
                <li><strong>Client ID:</strong> <code>seo_app</code> ✅ Configured</li>
            </ul>
            <p><em>Make sure your OAUTH_REDIRECT_URI environment variable is set to: <code>https://seo.daveenci.ai/auth/callback</code></em></p>
        </div>
        <hr>
        <p><strong>OAuth Endpoints:</strong></p>
        <ul>
            <li>Authorization: <code>${process.env.OAUTH_AUTHORIZE_URL || `${AUTH_SERVER_URL}${process.env.OAUTH_AUTHORIZE_PATH || '/oauth/authorize'}`}</code></li>
            <li>Token: <code>${process.env.OAUTH_TOKEN_URL || `${AUTH_SERVER_URL}${process.env.OAUTH_TOKEN_PATH || '/oauth/token'}`}</code></li>
            <li>User Info: <code>${process.env.OAUTH_USERINFO_URL || `${AUTH_SERVER_URL}/oauth/userinfo`}</code></li>
        </ul>
        <p><strong>Security Features:</strong></p>
        <ul>
            <li>✅ CSRF Protection: State parameter automatically generated</li>
            <li>✅ State Validation: Prevents replay attacks</li>
            <li>✅ State Expiration: 10-minute timeout</li>
            <li>✅ Configurable Scopes: Set via OAUTH_SCOPES environment variable</li>
        </ul>
        <hr>
        <p><a href="/login">Click here to initiate the OAuth/OIDC login flow</a></p>
        <p>Check the server logs on Render for more details during the flow.</p>
    `);
});

// 2. Initiate OAuth/OIDC Login Flow
app.get('/login', (req, res) => {
    // Generate a random state parameter for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    
    // Store state with timestamp (expire after 10 minutes)
    stateStore.set(state, { timestamp, used: false });
    
    // Clean up expired states (older than 10 minutes)
    const tenMinutesAgo = Date.now() - (10 * 60 * 1000);
    for (const [key, value] of stateStore.entries()) {
        if (value.timestamp < tenMinutesAgo) {
            stateStore.delete(key);
        }
    }
    
    // Use full URL if provided, otherwise construct from base URL + path
    const authorizeBaseUrl = process.env.OAUTH_AUTHORIZE_URL || 
                            `${AUTH_SERVER_URL}${process.env.OAUTH_AUTHORIZE_PATH || '/oauth/authorize'}`;
    
    // Construct the authorization URL with state parameter
    // Adjust 'response_type' and 'scope' based on your auth server's requirements (e.g., 'code', 'id_token', 'token')
    const authUrl = `${authorizeBaseUrl}?` +
                    `client_id=${OAUTH_CLIENT_ID}&` +
                    `redirect_uri=${encodeURIComponent(OAUTH_REDIRECT_URI)}&` +
                    `response_type=code&` + // Assuming Authorization Code Flow
                    `scope=${encodeURIComponent(OAUTH_SCOPES)}&` + // Configurable scopes
                    `state=${state}`; // CSRF protection

    console.log(`Initiating OAuth flow with state: ${state}`);
    console.log(`Redirecting to: ${authUrl}`);
    res.redirect(authUrl);
});

// 3. OAuth/OIDC Callback Endpoint
// This is where your authentication server will redirect the user back to after successful authentication.
// This route's path must match the path in your OAUTH_REDIRECT_URI (e.g., '/auth/callback')
app.get('/auth/callback', async (req, res) => {
    const authorizationCode = req.query.code;
    const state = req.query.state;
    const error = req.query.error;
    const errorDescription = req.query.error_description;

    if (error) {
        console.error(`OAuth Callback Error: ${error} - ${errorDescription}`);
        return res.status(400).send(`Authentication failed: ${errorDescription || error}`);
    }

    if (!authorizationCode) {
        console.error('OAuth Callback: No authorization code received.');
        return res.status(400).send('Authentication failed: No code received.');
    }

    // Validate state parameter for CSRF protection
    if (!state) {
        console.error('OAuth Callback: No state parameter received.');
        return res.status(400).send('Authentication failed: No state parameter received.');
    }

    const stateData = stateStore.get(state);
    if (!stateData) {
        console.error(`OAuth Callback: Invalid or expired state parameter: ${state}`);
        return res.status(400).send('Authentication failed: Invalid or expired state parameter.');
    }

    if (stateData.used) {
        console.error(`OAuth Callback: State parameter already used: ${state}`);
        return res.status(400).send('Authentication failed: State parameter already used.');
    }

    // Mark state as used to prevent replay attacks
    stateData.used = true;
    stateStore.set(state, stateData);

    console.log(`Received Authorization Code: ${authorizationCode}`);
    console.log(`State validation successful: ${state}`);

    // --- Exchange the Authorization Code for Tokens ---
    // This part requires making a POST request to your authentication server's token endpoint.
    const tokenUrl = process.env.OAUTH_TOKEN_URL || 
                    `${AUTH_SERVER_URL}${process.env.OAUTH_TOKEN_PATH || '/oauth/token'}`;
    
    try {
        const tokenResponse = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: OAUTH_CLIENT_ID,
                client_secret: OAUTH_CLIENT_SECRET, // Make sure your server protects this!
                redirect_uri: OAUTH_REDIRECT_URI,
                code: authorizationCode
            }).toString()
        });

        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json();
            throw new Error(`Token exchange failed: ${tokenResponse.status} ${tokenResponse.statusText} - ${JSON.stringify(errorData)}`);
        }

        const tokens = await tokenResponse.json();
        console.log('Successfully exchanged code for tokens:', tokens);

        // Here, you would typically store the access_token, id_token, and refresh_token
        // in a secure manner (e.g., in a session for server-side apps, or HttpOnly cookies).
        // Then, redirect the user to a secure area of your application.

        res.send(`
            <h1>Authentication Successful!</h1>
            <p>Authorization Code received and exchanged for tokens.</p>
            <p>Check server logs for token details.</p>
            <p><pre>${JSON.stringify(tokens, null, 2)}</pre></p>
            <p><a href="/">Go back to home</a></p>
        `);

    } catch (tokenExchangeError) {
        console.error('Error during token exchange:', tokenExchangeError.message);
        res.status(500).send(`Authentication failed during token exchange: ${tokenExchangeError.message}`);
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`App URL configured: ${APP_URL}`);
    console.log(`Auth Server URL: ${AUTH_SERVER_URL}`);
    console.log(`OAuth Client ID: ${OAUTH_CLIENT_ID}`);
    console.log(`OAuth Redirect URI: ${OAUTH_REDIRECT_URI}`);
}); 