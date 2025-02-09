// Call the async function

const fetch = require('node-fetch');
const { createDpopHeader, generateDpopKeyPair } = require('@inrupt/solid-client-authn-core');
const { buildAuthenticatedFetch } = require('@inrupt/solid-client-authn-core');


async function loginAndGetAuthorization() {
  try {
    // First we request the account API controls to find out where we can log in
    const indexResponse = await fetch('http://localhost:3000/.account/');
    const { controls } = await indexResponse.json();

    // And then we log in to the account API
    const response = await fetch(controls.password.login, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'alice@gmail.com', password: 'alice' }),
    });
    // This authorization value will be used to authenticate in the next step
    const { authorization } = await response.json();
    console.log('Authorization:', authorization);
    return authorization;
  } catch (error) {
    console.error('Error:', error);
  }
}

async function getToken(authorization) {
  console.log('get Token Authorization:', authorization);
  try {
    // Now that we are logged in, we need to request the updated controls from the server.
    // These will now have more values than in the previous example.
    const indexResponse = await fetch('http://localhost:3000/.account/', {
      headers: { authorization: `CSS-Account-Token ${authorization}` }
    });
    const { controls } = await indexResponse.json();

    // Here we request the server to generate a token on our account
    const response = await fetch(controls.account.clientCredentials, {
      method: 'POST',
      headers: { authorization: `CSS-Account-Token ${authorization}`, 'content-type': 'application/json' },
      // The name field will be used when generating the ID of your token.
      // The WebID field determines which WebID you will identify as when using the token.
      // Only WebIDs linked to your account can be used.
      body: JSON.stringify({ name: 'my-token', webId: 'http://localhost:3000/alice/profile/card#me' }),
    });

    // These are the identifier and secret of your token.
    // Store the secret somewhere safe as there is no way to request it again from the server!
    // The `resource` value can be used to delete the token at a later point in time.
    const { id, secret, resource } = await response.json();
    console.log('token:', { id, secret, resource });
    return { id, secret, resource };
  } catch (error) {
    console.error('Error:', error);
  }
}



async function getAccessToken(id, secret, dpopKey) {
  try {
    // A key pair is needed for encryption.
    // This function from `solid-client-authn` generates such a pair for you.

    // These are the ID and secret generated in the previous step.
    // Both the ID and the secret need to be form-encoded.
    const authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
    // This URL can be found by looking at the "token_endpoint" field at
    // http://localhost:3000/.well-known/openid-configuration
    // if your server is hosted at http://localhost:3000/.
    const tokenUrl = 'http://localhost:3000/.oidc/token';
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        // The header needs to be in base64 encoding.
        authorization: `Basic ${Buffer.from(authString).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
        dpop: await createDpopHeader(tokenUrl, 'POST', dpopKey),
      },
      body: 'grant_type=client_credentials&scope=webid',
    });

    // This is the Access token that will be used to do an authenticated request to the server.
    // The JSON also contains an "expires_in" field in seconds,
    // which you can use to know when you need request a new Access token.
    const { access_token: accessToken } = await response.json();
    console.log('AccessToken:', accessToken);
    return accessToken;
  } catch (error) {
    console.error('Error:', error);
  }

}

async function makeAuthenticatedRequest(accessToken, dpopKey) {
  try {
    // The DPoP key needs to be the same key as the one used in the previous step.
    // The Access token is the one generated in the previous step.
    const authFetch = await buildAuthenticatedFetch(accessToken, { dpopKey });
    // authFetch can now be used as a standard fetch function that will authenticate as your WebID.
    // This request will do a simple GET for example.
    const response = await authFetch('http://localhost:3000/alice/profile/card');
    console.log('AuthReq:', response);
    return response;
  } catch (error) {
    console.error('Error:', error);
  }
}
// Create an async function to orchestrate the calls
async function main() {
  try {
    // Await the authorization token from the login function
    const authorization = await loginAndGetAuthorization();

    const dpopKey = await generateDpopKeyPair();

    // Pass the authorization token to the getToken function
    token = await getToken(authorization);
    accessToken = await getAccessToken(token.id, token.secret,dpopKey);
    response= await makeAuthenticatedRequest(accessToken, dpopKey);
    return response;
  } catch (error) {
    console.error('Error:', error);
  }
}

// Execute the main function
main();
