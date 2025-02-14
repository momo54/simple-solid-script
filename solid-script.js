// Call the async function

const fetch = require('node-fetch');
const { createDpopHeader, generateDpopKeyPair } = require('@inrupt/solid-client-authn-core');
const { buildAuthenticatedFetch } = require('@inrupt/solid-client-authn-core');

const {
  getSolidDatasetWithAcl,
  hasResourceAcl,
  hasAccessibleAcl,
  hasFallbackAcl,
  createAcl,
  createAclFromFallbackAcl,
  getResourceAcl,
  setAgentResourceAccess,
  saveAclFor,
} = require("@inrupt/solid-client");

const { getFile, getContentType, getSourceUrl } =require('@inrupt/solid-client');

// Le WebID de Bob (à adapter)
const bobWebId = "http://localhost:3000/bob/profile/card#me";
const fileUrl = "http://localhost:3000/alice/private/private-document.txt";


// URL de l'ACL (habituellement, c'est l'URL du fichier suivi de ".acl")
const aclUrl = fileUrl + ".acl";

// Contenu ACL pré-formaté (en Turtle)
// Dans cet exemple, on définit deux autorisations :
//  - Une pour l'agent propriétaire (Alice) avec tous les droits
//  - Une pour Bob avec uniquement le droit de lecture
const aclContent = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.

<#owner>
    a acl:Authorization;
    acl:agent <http://localhost:3000/alice/profile/card#me>;
    acl:accessTo <${fileUrl}>;
    acl:default <http://localhost:3000/alice/private/>;
    acl:mode acl:Read, acl:Write, acl:Control.

<#readAuth>
    a acl:Authorization;
    acl:agent <http://localhost:3000/bob/profile/card#me>;
    acl:accessTo <${fileUrl}>;
    acl:mode acl:Read.
`;


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

async function BobloginAndGetAuthorization() {
  try {
    // First we request the account API controls to find out where we can log in
    const indexResponse = await fetch('http://localhost:3000/.account/');
    const { controls } = await indexResponse.json();

    // And then we log in to the account API
    const response = await fetch(controls.password.login, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'bob@gmail.com', password: 'bob' }),
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

async function BobgetToken(authorization) {
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
      body: JSON.stringify({ name: 'my-token', webId: 'http://localhost:3000/bob/profile/card#me' }),
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

async function makeAuthenticatedRequest(authFetch) {
  try {
    const response = await authFetch('http://localhost:3000/alice/profile/card');
    console.log('AuthReq:', response);
    return response;
  } catch (error) {
    console.error('Error:', error);
  }
}

async function readPrivate(authFetch) {
  try {
    const response = await authFetch(fileUrl);
    console.log('AuthReq:', response);
    return response;
  } catch (error) {
    console.error('Error:', error);
  }
}


async function createPrivateFile(authFetch) {
//    const fileUrl = "http://localhost:3000/alice/private/private-document.txt";  // Adjust the URL based on your server

    const fileContent = "This is a private document for Bob.";
    
    const response = await authFetch(fileUrl, {
        method: "PUT",
        headers: {
            "Content-Type": "text/plain"
        },
        body: fileContent
    });

    console.log("File creation response:", response.status);
    return response;
}

async function readFile(fileUrl, authFetch) {
  try {
    // Récupérer le fichier depuis le POD
    const file = await getFile(fileUrl, { fetch: authFetch });
    
    // Par exemple, convertir le Blob en texte :
    const fileText = await file.text();
    console.log("Contenu du fichier :", fileText);
    
    // Vous pouvez aussi obtenir le type de contenu ou l’URL source :
    console.log("Type MIME :", getContentType(file));
    console.log("URL source :", getSourceUrl(file));
  } catch (error) {
    console.error("Erreur lors de la lecture du fichier :", error);
  }
}

// async function autoriserBob(authFetch) {
//   // Récupérer le dataset du fichier avec son ACL
//   const datasetWithAcl = await getSolidDatasetWithAcl(fileUrl, { authFetch });
  
//   // Récupérer ou créer l'ACL spécifique au fichier
//   let resourceAcl;
//   if (!hasResourceAcl(datasetWithAcl)) {
//     if (!hasAccessibleAcl(datasetWithAcl)) {
//       throw new Error("Alice n'a pas les droits pour modifier l'ACL de ce fichier.");
//     }
//     if (!hasFallbackAcl(datasetWithAcl)) {
//       resourceAcl = createAcl(datasetWithAcl);
//     } else {
//       resourceAcl = createAclFromFallbackAcl(datasetWithAcl);
//     }
//   } else {
//     resourceAcl = getResourceAcl(datasetWithAcl);
//   }
  
//   // Modifier l'ACL pour donner à Bob un accès en lecture (read: true) seulement
//   const updatedAcl = setAgentResourceAccess(
//     resourceAcl,
//     bobWebId,
//     { read: true, append: false, write: false, control: false }
//   );
  
//   // Sauvegarder l’ACL mis à jour dans le POD
//   await saveAclFor(datasetWithAcl, updatedAcl, { fetch });
  
//   console.log(`Accès en lecture accordé à Bob (${bobWebId}) pour le fichier ${fileUrl}`);
// }


async function uploadAcl(authFetch) {
  try {
    const response = await authFetch(aclUrl, {
      method: "PUT",
      headers: {
        "Content-Type": "text/turtle",
      },
      body: aclContent,
    });

    if (!response.ok) {
      console.error(`Erreur lors du PUT ACL : ${response.status} ${response.statusText}`);
    } else {
      console.log(`ACL uploadé avec succès à ${aclUrl}`);
    }
  } catch (error) {
    console.error("Erreur lors du PUT ACL :", error);
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
    const authFetch = await buildAuthenticatedFetch(accessToken, { dpopKey });
    mar = await makeAuthenticatedRequest(authFetch);
    cpf = await createPrivateFile(authFetch);
    mar = await readPrivate(authFetch);
//    const datasetWithAcl = await getSolidDatasetWithAcl(fileUrl, { authFetch });
//    saf= await autoriserBob(authFetch);
    await readFile(fileUrl, authFetch);
    await uploadAcl(authFetch);

    console.log("-----------------------")

    bobAuthreq = await BobloginAndGetAuthorization();
    bobToken = await BobgetToken(bobAuthreq);
    bobAccessToken = await getAccessToken(bobToken.id, bobToken.secret,dpopKey);

    const bobFetch = await buildAuthenticatedFetch(bobAccessToken, { dpopKey });
    await readFile(fileUrl, bobFetch);

  } catch (error) {
    console.error('Error:', error);
  }
}

// Execute the main function
main();
