Solid Login is hard
- https://solidproject.org/TR/oidc-primer

The CSS solid server has a complex configuration that can be inspected with:
```
curl http://localhost:3000/.well-known/openid-configuration | jq
```

The only way to login in the CSS server is to follow OIDC workflow. The workflow is complex and detailed in https://solidproject.org/TR/oidc-primer

The solid-node-client have been used by capstone project (https://gitlab.univ-nantes.fr/E205936T/solid_fediscount). But the login is only supported on the NSS server and *not* the CSS server !!

The OIDC workflow relies on :
- create credential token for users (login on the wen interface and create credential token)
- use credential token to register appli client id / appli secret 
- use appli ID/Secret for login.

Lets read the doc : https://communitysolidserver.github.io/CommunitySolidServer/latest/ 

So At end:
- start the server : npx @solid/community-server -c @css:config/file.json -f data/
- Register an account at http://localhost:3000/.account/login/password/register with login = alice@gmail.com, passwd=alice
- Once Logged, create a Credential token, for example : alice_token_64edab4e-473a-444b-ba06-284b649e7f63
- Update solid-script.js with Credential token
- maybe install some solid package with NPM.
- run : node solid-script.js