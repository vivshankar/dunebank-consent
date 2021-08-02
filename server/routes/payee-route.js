// import dependencies and initialize the express router
const Express = require('express');
const PayeeHandler = require('../controllers/payee-controller');

const payeeHandler = new PayeeHandler();
const router = Express.Router();
const jsonParser = Express.json();

// define routes
router.post('/authorize', jsonParser, payeeHandler.authorize);
router.get('/consent', payeeHandler.consent);
router.post('/consents', jsonParser, payeeHandler.storeConsents);

module.exports = router;