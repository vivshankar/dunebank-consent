## Introduction

It is typical in the financial industry to have a ecosystem of services - utilities, wealth management, insurance, etc. - that require a relationship established with a bank to authorize recurring transfers and transactions. There are generally three parties involved:

1. Bank or other financial institution where the payee needs to be added
2. Bank identity provider: User authenticates with bank credentials before authorizing a request
3. Third-party provider (TPP): Usually an entity that offers various services like insurance. The TPP usually offers the user the option of setting up a Direct Debit relationship with banks etc., to simplify the process of transferring premiums and funds.

In this architecture, the TPP cannot be allowed to modify the consent information on the user's behalf because the TPP is not a trusted entity. Moreover, the TPP would usually not authenticate the user using bank credentials. Given this restriction, the bank controls the privacy assessment and consent process that results in user authorization.

This guide will walk you through how to build a centralized bank-owned consent app that leverages [IBM Security Verify Privacy](https://docs.verify.ibm.com/verify/docs/user-privacy-and-consent) capabilities in a native NodeJS application using the Beta version of the [Privacy SDK](https://github.com/vivshankar/verify-privacy-sdk-js). This app would be leveraged by third-party provider services like [Ingots Wealth Service](https://github.com/vivshankar/ingots-wealth-service).

This sample app provides:

1. An API `/payee/authorize` that checks whether the requested data items are already authorized and, if not, whether the user can consent to them.
2. Consent page that presents a standardized user experience and collects consent that the consent app is authorized to store on the consent management system.

The typical lifecycle expected here is illustrated below.

![](https://www.planttext.com/api/plantuml/img/bLNBZXCn4BpFLxHou74Wl6uhyTY7X098HEm25oJasBqPQoVsO7isoiB-EzKUpsOc2mToY2AxkbrTNTrv6vCAgTiqLQLqye6wo85KfDbxZj5gDQjMldD6XHrrAb-S1By5Q5QrYBJQjiebIcsRBozg6ymJkTaHGDTMynIe-oHddUELSbUalOkCSzMsKw0rxHIvC4jwj3Z_-dXMLPdbazUWT4JdtMfZ4xN1cqudCfoKRM85jW20rpyHmdc0d7bQKAskcHGbVyMEBeFVKAgPvF4tFRYyk70sMPM0lN4em31TDdwBE5fpwiFByoZYY3vOVKN-yl8ENabjGxBJMZKDkpMItCdVfNfIuZ4E81BQWKUtDjNKQnVOoB6wApU_LyeTt-O7o_KxTXmaqQV5sMbXEn3gvM9dnfT59mqYJrkrOtug17smDqo_CxSR-fMXjvNUqrYu57ni6OgBZ0KngAGR2t8_h265rpmGWOnAQfnXoG6QRD0uUwtq3dQ8CEK6SMFKEybMNBH1QqTPXF99Pnj3xxzT20YDTzQjx-65n7TtiLmUyCfDM9oHTmJdvQo3IXYSrCLN9TC3Y6q3QlqIxAjVvN092xNfo-UFjnFxl7psWlu2SHuzyTTu4E2Ay3asXjBMap86XlDEDVIpOqnYJ46gmBWeLC0X7cLy_de-9zt5v3T7X66CqC3H2bPrkt9EAY5yrIMEqWovCuQD_9O-3TAW61zCJla2AM7IbT9NA4_oCe6oH6nhg-j970Rvkukrxw3w80hqqtj4ZR5UCSiimFawiQd4SL9_LNmiZVkBH4N_F3ObMQlMV6zMUcyAgy1GBAPHsc4w-lXuw2JnccrudGKHz-_RebLMu-HWRH54NWUiB8IeSVpnSf43Uak1Zag2XOkzblLX-b4McgErcKFAwfG5YFRDZjksaU671oGhdUQCisBB-Rxvqfbx_3OmlHWVkV2xRM6T35vnsaeR3WX8pCEu7uICbM58OgTHVQMk_PwPx_iuKlKSVoiyrNio27jdtVQ26DOsejJn2f_0_diZ3LcWOq0hpU7gpslUtipdywfwYnhmV_W7)

## Pre-requisites

1. Install Node and Git on your machine
2. [Create a tenant on IBM Security Verify](https://docs.verify.ibm.com/verify/docs/signing-up-for-a-free-trial). This is the Bank identity provider.
3. Clone this repo to your machine

## Setup

In order to configure this application, you will need a TPP registered on the IBM Security Verify tenant that represents the bank IdP.

Before you start, copy the `dotenv` file and name it `.env`

### Create the TPP application and configure

1. Follow the steps to [onboard the TPP application](https://github.com/vivshankar/ingots-wealth-service)
2. Within the TPP application > Sign On tab, copy the Client ID. We will refer to this as `{{tppClientId}}` in the steps below.
3. Within the TPP application > API Access tab, an API client was created as part of step 1 called "Bank Consent Client". Copy the client ID and secret. We will refer to this as `{{apiClientId}}` and `{{apiClientSecret}}` in the steps below.
4. Open the .env file
5. Modify the TPP_MAP as `{"{{tppClientId}}":"{{apiClientId}}:{{apiClientSecret}}"}`. Replace the placeholders based on the values in steps 2 and 3.

This creates an association between the client ID used by the TPP application with the API client that is authorized to perform the assessment and store consents associated with the TPP application.

### Create Bank Consent App API Client

1. Login to Verify Admin Console
2. Go to Configuration > API Access
3. Add an API client. At the moment, no entitlements need to be provided for this client because it is merely a placeholder to represent the Bank Consent App.
4. Copy the client ID and client secret, and set the values in the .env file for `CLIENT_ID` and `CLIENT_SECRET` respectively.

## Run the application

1. Install node dependencies

    ```bash
    npm install
    ```

2. Run the application. You should see `Server started and listening on port 3001` after executing the command below.

    ```bash
    npm start
    ```

3. Run [Ingots Wealth Service](https://github.com/vivshankar/ingots-wealth-service).

This application is used during the process of adding a wealth product in Ingots Wealth Service.

## Browsing the code

The project structure is described [here](/docs/browsing_code.md)