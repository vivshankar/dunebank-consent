The repository is structured to separate views, Express routes & controllers, external service clients and utilities.

- /index.js: This is the entrypoint to the app that just initializes `server`
- /server/server.js: This contains the actual "main" function code. It sets up the app server and starts it up.
- /server/config.js: The configuration object loaded using dotenv
- /server/routes: These are express routes that route requests made to specific URL paths to their corresponding handler function in the controller.
- /server/controllers: The different HTTP handlers that handles the request and response.
- /server/services: External services and utilities used by controllers. For example, a TokenService would contain functions to introspect a token, get a token using an API-based grant flow, etc.
- /views: The express handlebar layout and view templates
- /public: Images and stylesheets that are served statically