const config = require('../../config').Config;
const HTTPUtil = require('../httputil');
const httpClient = new HTTPUtil(config.tenantUrl);
        
class TokenService {

    getToken = async (tppClientId) => {

        // TODO: Add a cache storage to reduce grants

        let clientIdSecret = config.tppMap[tppClientId];
        let tokens = clientIdSecret.split(":");
        const response = await httpClient.post("/oidc/endpoint/default/token", {
            "grant_type": "client_credentials",
            "client_id": tokens[0],
            "client_secret": tokens[1],
        }, {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        });

        return response.data;
    }

    introspect = async (accessToken) => {
        const response = await httpClient.post('/oidc/endpoint/default/introspect', {
            "client_id": config.clientId,
            "client_secret": config.clientSecret,
            "token": accessToken,
        }, {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        });

        return response.data;
    }

    logout = (req) => {

        if (!this.isLoggedIn(req)) {
            return;
        }

        // TODO: should probably revoke the token

        req.session.destroy();
    }

    isLoggedIn = (req) => {
        return req.session != null && req.session.authToken != null && req.session.authToken != "";
    }
}

module.exports = TokenService;