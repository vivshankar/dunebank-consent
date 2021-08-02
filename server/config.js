// load contents of .env into process.env
require('dotenv').config();

exports.Config = {
    tenantUrl    : process.env.TENANT_URL,
    clientId     : process.env.CLIENT_ID,
    clientSecret : process.env.CLIENT_SECRET,
    tppMap       : JSON.parse(process.env.TPP_MAP),
};