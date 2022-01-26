const PORT = process.env.PORT || 3001;

// initialize libraries
const express = require('express');
const session = require('express-session')
const handlebars = require('express-handlebars');
const payeeRoutes = require('./routes/payee-route');

// initialize handlebars
var hbs = handlebars.create({
    helpers: {
        formatPurpose: function (purposeName, version) {
            if (purposeName == 'ibm-oauth-scope') {
                return 'OAuth Scope';
            }

            return `${purposeName} (Version ${version})`
        },
        formatDate: function (badDate) {
            var dMod = new Date(badDate * 1000);
            return dMod.toLocaleDateString('en-GB', {
                day: 'numeric', month: 'short', year: 'numeric'
              });
            //return dMod.toLocaleDateString();
        },
        formatState: function (state) {
            var stateOpt = {
                1: "Consent allow",
                2: "Consent deny",
                3: "Opt-in",
                4: "Opt-out",
                5: "Transparent"
            }
            return stateOpt[state];
        },
        formatAccessType: function (accessType) {
            if (accessType == "default") {
                return "";
            }
            return accessType;
        },
        formatAttribute: function (attribute) {
            if (attribute == "") {
                return "–";
            }
            else {
                return attribute;
            }
        },
        isApprovedConsent: function (record, options) {
            if (record.status != "ACTIVE") {
                return options.inverse(this);
            }

            if (record.consent == null) {
                return options.inverse(this);
            }

            if (record.consent.state == 2 || record.consent.state == 4) {
                return options.inverse(this);
            }

            return options.fn(this);
        },
        formatConsentDetails: function (record) {
            let t = 'Amount ';
            let amt = '-';
            if (record.consent != null && record.consent.customAttributes != null) {
                var formatter = new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD',
                });

                for (const attr of record.consent.customAttributes) {
                    if (attr['name'] == 'amount') {
                        amt = formatter.format(Number(attr['value']));
                        break;
                    }
                }
            }

            t += amt + ' from ';
            try {
                let val = JSON.parse(record.attributeValue);
                t += val.accnum;
            } catch (e) {
                t += record.attributeValue;
            }

            return t;
        },
        currentConsentAmount: function (record) {
            let amt = '';
            if (record.consent != null && record.consent.customAttributes != null) {
                for (const attr of record.consent.customAttributes) {
                    if (attr['name'] == 'amount') {
                        amt = attr['value']
                        break;
                    }
                }
            }

            return amt;
        },
        'json': function (context) {
            return JSON.stringify(context);
        },
        'concat': function (str, suffix) {
            if (typeof str === 'string' && typeof suffix === 'string') {
                return str + suffix;
            }
            return str;
        },
    },
    layoutsDir: __dirname + '/../views/layouts',
    partialsDir: __dirname + '/../views/partials',
    extname: 'hbs',
    defaultLayout: 'default',
});

// initialize the app
const app = express();
app.set('view engine', 'hbs');
app.engine('hbs', hbs.engine)

app.use(session({
    secret: 'supersecret',
    resave: false,
    saveUninitialized: true,
    cookie: { path: '/', maxAge: 30 * 60 * 1000, secure: false }
}))

// define routes
app.use(express.static(__dirname + '/../public'))
app.use('/payee', payeeRoutes);
app.use('/domestic-payments', require('./routes/domestic-payments-route'));
app.use('/internal', require('./routes/internal-route'));

app.listen(PORT, () => {
    console.log(`Server started and listening on port ${PORT}`);
});