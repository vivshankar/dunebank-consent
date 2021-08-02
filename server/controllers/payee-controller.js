// Load dependencies
const JWT = require('jsonwebtoken');
const TokenService = require('../services/oauth/tokenService');
const Privacy = require('verify-privacy-sdk-js');
const debug = require('debug')('dunebank:consent');

// Initialize global variables
const tokenService = new TokenService();
const config = require('../config').Config;

class PayeeController {

    authorize = async (req, res) => {

        // Extract access token
        const accessToken = this._extractToken(req);
        if (accessToken == null) {
            res.status(401).send('Not authorized');
            return;
        }

        // Introspect to get uid and applicationId
        const tokenData = await tokenService.introspect(accessToken);
        if (!tokenData.active) {
            res.status(401).send('Not authorized');
            return;
        }

        // Assess
        const privacy = new Privacy(config, { accessToken: accessToken }, {});
        const items = req.body.items;

        debug(`[${PayeeController.name}:authorize]`,
            `Assessment request:\n${JSON.stringify(items, null, 2)}`);

        let decision = await privacy.assess(items);
        debug(`[${PayeeController.name}:authorize]`,
            `Assessment response:\n${JSON.stringify(decision, null, 2)}`);

        let response = {
            status: decision.status,
        };

        if (decision.status == "consent") {
            // filter the list based on those that can be consented
            let items = [];
            for (const assess of decision.assessment) {
                for (const iaresult of assess.result) {
                    const attrId = (assess.attributeId) ? assess.attributeId : iaresult.attributeId;
                    const attrValue = (assess.attributeValue) ? assess.attributeValue : iaresult.attributeValue;
                    const assessLog = `${assess.purposeId},${attrId},${assess.accessTypeId},${attrValue},${JSON.stringify(iaresult)}`;
                    if (!iaresult.requiresConsent) {
                        debug(`[${PayeeController.name}:authorize]`,
                            `Requires no consent: `, assessLog)
                        continue;
                    }
        
                    debug(`[${PayeeController.name}:authorize]`,
                        `Requires consent: ${assessLog}`)
                    items.push({
                        purposeId: assess.purposeId,
                        attributeId: attrId,
                        accessTypeId: assess.accessTypeId,
                        attributeValue: attrValue,
                    });
                }
            }

            // metadata used to render a user consent page
            debug(`[${PayeeController.name}:authorize]`,
                `Metadata request:\n${JSON.stringify(items, null, 2)}`);
            let r = await privacy.getConsentMetadata(items);
            debug(`[${PayeeController.name}:authorize]`,
                `Metadata response:\n${JSON.stringify(r, null, 2)}`);

            // TODO: Switch to using RS256
            const jwt = JWT.sign({
                uid: tokenData.uniqueSecurityName,
                appId: tokenData.app_id,
                clientId: tokenData.client_id,
                metadata: r.metadata,
            }, 'supersecret');
            response.redirectUri = `/payee/consent?jwt=${jwt}`;
            
            res.status(200).send(response);
        } else if (decision.status == "approved") {
            res.status(200).send(response);
        } else if (decision.status == "denied" || decision.status == "multistatus") {
            res.status(403).send(response);
        } else if (decision.status == "error") {
            console.error(`[${PayeeController.name}:authorize]`,
                `Something catastrophic happened\nJSON.stringify(decision.error, null, 2)`);
            res.status(500).send(response);
        }
    }

    consent = async (req, res) => {

        // Get the JWT and decode
        let r = null;
        try {
            r = JWT.decode(req.query.jwt, 'supersecret');
        } catch(err) {
            console.error(`Unable to decode the JWT ${req.query.jwt}; err=${err}`);
            res.status(400).send('Malformed input');
            return;
        }

        let callbackUri = decodeURIComponent(req.query.callbackUri);
        let customAttributes = null;
        if (req.query.custom) {
            customAttributes = JSON.parse(req.query.custom);
        }

        for (let record of r.metadata.default) {
            let message = await this._buildConsentMessage(record);
            record.id = record.purposeId + record.attributeId + record.accessTypeId + record.attributeValue;
            record.message = message;
            record.customAttributes = customAttributes;
            record.subjectId = r.uid;
            record.applicationId = r.appId;
        }

        res.render('consentPrompt', { consents: r.metadata.default,
            title: "Consent request", callbackUri: callbackUri, tppClientId: r.clientId });
    }

    storeConsents = async (req, res) => {

        const token = await tokenService.getToken(req.body.tppClientId);
        const auth = {
            accessToken: token.access_token,
        };

        const privacy = new Privacy(config, auth, {})

        debug(`[${PayeeController.name}:storeConsents]`,
            `Store consents:\n${JSON.stringify(req.body, null, 2)}`);
        // assuming the request.body.consents is a JSON array of 
        // consent records that need to be stored
        let r = await privacy.storeConsents(req.body.consents);
        debug(`[${PayeeController.name}:storeConsents]`,
            `Store consents response:\n${JSON.stringify(r, null, 2)}`);

        res.send({ callbackUri: req.body.callbackUri + "?decision=" + r.status });
    }

    _extractToken = (req) => {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
            return req.query.token;
        }

        return null;
    }

    _buildConsentMessage = async (record) => {
        let str = "Allow";
        if (record.accessTypeId != "default") {
            str += ` ${record.accessType} access`;
        } else {
            str += " access";
        }

        if (record.attributeId != null) {
            str += ` to my ${record.attributeName.toLowerCase()}`;
        }

        str += ` to ${record.purposeName.toLowerCase()}`;
        return str;
    }
}

module.exports = PayeeController;