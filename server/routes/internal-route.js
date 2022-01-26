// import dependencies and initialize the express router
const Express = require('express');
const Handler = require('../controllers/domestic-payments-controller');

const handler = new Handler();
const router = Express.Router();

// define routes
router.get('/intents/:intentId', handler.getContext);

module.exports = router;