const express = require('express');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000; // Render provides the PORT environment variable

// --- Accessing your Environment Variables ---
const APP_URL = process.env.APP_URL; // This should be 'https://seo.daveenci.ai'
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL;
const DATABASE_URL = process.env.DATABASE_URL; // Might not be directly used in this simple test app
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
// The OAUTH_REDIRECT_URI *must* match the URL where your auth server will redirect back to this app.
// For Render, this will be your custom domain + path, e.g., 'https://seo.daveenci.ai/oauth/callback'
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET; // Used for session management, if you implement it

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
        <p><a href="/login">Click here to initiate the OAuth/OIDC login flow</a></p>
        <p>Check the server logs on Render for more details during the flow.</p>
    `);
});

// 2. Initiate OAuth/OIDC Login Flow
app.get('/login', (req, res) => {
    // Construct the authorization URL
    // Adjust 'response_type' and 'scope' based on your auth server's requirements (e.g., 'code', 'id_token', 'token')
    const authUrl = `${AUTH_SERVER_URL}/authorize?` +
                    `client_id=${OAUTH_CLIENT_ID}&` +
                    `redirect_uri=${encodeURIComponent(OAUTH_REDIRECT_URI)}&` +
                    `response_type=code&` + // Assuming Authorization Code Flow
                    `scope=openid profile email offline_access`; // Adjust scopes as needed

    console.log(`Initiating OAuth flow. Redirecting to: ${authUrl}`);
    res.redirect(authUrl);
});

// 3. OAuth/OIDC Callback Endpoint
// This is where your authentication server will redirect the user back to after successful authentication.
// This route's path must match the path in your OAUTH_REDIRECT_URI (e.g., '/api/auth/callback')
app.get('/api/auth/callback', async (req, res) => {
    const authorizationCode = req.query.code;
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

    console.log(`Received Authorization Code: ${authorizationCode}`);

    // --- Exchange the Authorization Code for Tokens ---
    // This part requires making a POST request to your authentication server's token endpoint.
    
    try {
        const tokenResponse = await fetch(`${AUTH_SERVER_URL}/token`, {
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