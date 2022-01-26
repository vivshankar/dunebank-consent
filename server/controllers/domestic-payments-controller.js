// Load dependencies
const { uuid } = require('uuidv4');
const NodeCache = require( "node-cache" );
const debug = require('debug')('dunebank:consent');

// Initialize global variables
const config = require('../config').Config;
var intentStore = new NodeCache( { stdTTL: 600, checkperiod: 120 } );

class DomesticPaymentsController {

    create = async (req, res) => {

        const id = uuid();
        let data = req.body
        // TODO: validate it
        
        intentStore.set(id, data, 600)
        res.status(200).send({
            ConsentId: id,
            Status: "AwaitingAuthorisation"
        });
    }

    getContext = async (req, res) => {
        let intentId = req.params.intentId
        if (!intentId || intentId == "") {
            console.error("Intent ID not provided");
            res.status(400).send({
                "error": "No intent provided"
            })
        }

        let data = intentStore.get(intentId)
        if (data == undefined) {
            res.status(404).send({intentId: intentId});
            return;
        }

        console.log(`DEBUG: ${intentId}=${JSON.stringify(data)}`)

        res.status(200).send(data);
    }
}

module.exports = DomesticPaymentsController;