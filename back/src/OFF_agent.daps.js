let
    https        = require("https"),
    jwt          = require("jsonwebtoken"),
    express      = require("express"),
    session      = require("express-session"),
    bodyParser   = require("body-parser"),
    cookieParser = require("cookie-parser")
;

module.exports = ({
                      'hrt':    hrt = () => (new Date).valueOf() / 1000,
                      'Helmut': Helmut
                      //'router': router
                      ,
                      'config': config
                  }) => {

    let
        daps,
        app   = express(),
        sess  = {
            'key':               'user_sid',
            'secret':            `${Math.random()}`, // TODO : random pwd?!? From Helmut?!?
            'resave':            false,
            'saveUninitialized': false,
            'cookie':            {
                'expires': 600000
            }
        },
        space = config['space']
    ; // let

    app.use(bodyParser['urlencoded']({'extended': true}));
    app.use(bodyParser['json']());
    app.use(cookieParser());

    if (app.get("env") === "production") {
        // Serve secure cookies, requires HTTPS
        sess['cookie']['secure'] = true;
    } // if ()
    app.use(session(sess));

    //let eventEmitter = new events.EventEmitter();

    //class DAPS extends events.EventEmitter {
    class DAPS extends require('events').EventEmitter {

        #server               = undefined; // !!!
        #app;
        #DAT_header_kid       = "default"; // TODO:config
        #DAT_header_algorithm = "HS256"; // TODO:config
        #DAT_token_expiration = (60 * 60); // 3600sec
        #issuer               = "";
        #audience             = "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL";
        #scope                = "ids_connector_attributes";
        #private_key;

        constructor(config, app) {

            super();

            this.#app                  = app;
            this.#DAT_header_kid       = config['DAT_header_kid'] || this.#DAT_header_kid;
            this.#DAT_header_algorithm = config['DAT_header_algorithm'] || this.#DAT_header_algorithm;
            this.#DAT_token_expiration = config['DAT_token_expiration'] || this.#DAT_token_expiration;
            this.#issuer               = (`${config['host']}${((config['port']) ? (`:${config['port']}`) : "")}` || this.#issuer);
            this.#audience             = config['audience'] || this.#audience;
            this.#scope                = config['scope'] || this.#scope;
            this.#private_key          = config['private_key'] || this.#private_key;

            if (this['__proto__']['constructor']['name'] === "DAPS") {
                //this['refs']['sealed'] = true;
                Object.seal(this);
            } // if ()

        } // constructor()

        getDAT({
                   //'assertion':                req['body']['assertion'],
                   'client_assertion':         client_assertion,
                   'client_assertion_type':    client_assertion_type,
                   'grant_type':               grant_type,
                   //
                   'requesterPeerCertificate': requesterPeerCertificate
               }) {
            return new Promise((resolve, reject) => {
                try {

                    let
                        // ZERO   : get decoded subject
                        decoded_token = jwt['decode'](client_assertion)
                        // FIRST  : get it from space
                    ;

                    space.get(decoded_token['iss']).then((identity) => {
                        if (!identity) {
                            reject(new Error(`TODO: no identity`));
                        } else {
                            jwt['verify'](
                                client_assertion,
                                //TODO: und genau dieser public key wir auch aus der DAPS-persistance geholt...
                                //`-----BEGIN CERTIFICATE-----\n${_connector['public_crt']}\n-----END CERTIFICATE-----`,
                                //`${_enum['BEGIN_CERTIFICATE']}${_connector['publicKey']}${_enum['END_CERTIFICATE']}`,
                                `${identity['cert']}`,
                                {
                                    'algorithms': ["RS256"]
                                    , 'maxAge':   1000 //REM: sec, TODO: maxAge >>> config
                                },
                                (err, verified_token) => {

                                    let
                                        skiaki
                                    ;

                                    if (err) {
                                        ////TODO: dieser Fehler trat dann wirklich mal auf, nach dem der client
                                        //// "SECRET" und nicht "RS256" übergabe!!!
                                        //switch (err['name']) {
                                        //    case "TokenExpiredError":
                                        //        reject({
                                        //            'type': "err", 'err': {
                                        //                '@type':     "TokenExpiredError",
                                        //                'message':   err['message'],
                                        //                'expiredAt': err['expiredAt'].toString()
                                        //            }
                                        //        });
                                        //        break; // TokenExpiredError
                                        //    default:
                                        //        reject({
                                        //            'type': "UnspecificError", 'UnspecificError': {}
                                        //        });
                                        //        break; // default
                                        //} // switch(err['name'])
                                        reject(err);

                                    } else {

                                        //skiaki = (verified['iss'] && (verified['iss'] === subject['CN'])) ? subject['CN'] : undefined;

                                        skiaki = `${verified_token['iss']}`;

                                        console.warn(`daps : ${(new Date).toISOString()} : skiaki : ${skiaki}`);

                                        //if (subjectAltName === skiaki) {
                                        if (skiaki) {

                                            // THIRD  : make token

                                            let
                                                iat        = Math.round((new Date).valueOf() / 1000),

                                                DAT_header = {
                                                    //'type':      DAT_header_type,
                                                    'keyid':     this.#DAT_header_kid, //TODO:config kid
                                                    'algorithm': this.#DAT_header_algorithm
                                                },
                                                DAT_token  = {
                                                    '@context':             "https://w3id.org/idsa/contexts/context.jsonld",
                                                    '@type':                "ids:DatPayload"
                                                    ,
                                                    'iss':                  this.#issuer,
                                                    'sub':                  skiaki,
                                                    //TODO: 'exp :: config/runtime
                                                    //'exp':                  Math.round(((new Date).valueOf() / 1000) + (60 * 60 * 24)),             // sec
                                                    'exp':                  Math.round(((new Date).valueOf() / 1000) + this.#DAT_token_expiration),             // sec
                                                    'iat':                  iat,                    // sec
                                                    'nbf':                  iat,                    // sec
                                                    'aud':                  this.#audience,
                                                    //
                                                    'scope':                [this.#scope]
                                                    ,
                                                    'referringConnector':   undefined, // 0..1,
                                                    'transportCertsSha256': [] // 0..*
                                                    ,
                                                    //'securityProfile':      "idsc:BASE_CONNECTOR_SECURITY_PROFILE",
                                                    'securityProfile':      identity['profile'],
                                                    'extendedGuarantee':    []
                                                }
                                            ; // let

                                            // FOURTH : sign token
                                            jwt['sign'](
                                                DAT_token,
                                                this.#private_key,
                                                DAT_header,
                                                (err, token) => {
                                                    if (err) {
                                                        reject({'type': "err", 'err': err});
                                                    } else {
                                                        //TODO:audit
                                                        //TODO:log
                                                        // FIFTH  : send DAT
                                                        resolve(token);
                                                    } // if()
                                                } // cb
                                            ); // jwt.sign
                                        } else {
                                            reject({
                                                'type': "err",
                                                's':    false,
                                                'err':  {'m': `subjectAltName '${subjectAltName}' differs from id-uuid '${skiaki}'`}
                                            });
                                        } // if ()
                                    } // if ()
                                }); // jwt.verify(body_token)
                        } // if ()

                    }).catch((err) => {
                        reject(err);
                    });

                } catch (jex) {
                    reject(jex);
                } // try
            }); // rnP
        } // getDAT

        //set request(value) {
        //    //TODO: do something with request...
        //}
        //
        //set notification(notification) {
        //    //TODO: do something with notification...
        //}

        listen() {
            return new Promise((resolve, reject) => {
                try {
                    this.emit('startListening', /** data */ {});
                    if (this.#server) {
                        resolve();
                    } else {

                        this.#server = https.createServer(config['https_server_options'], this.#app);

                        this.#server['listen'](config['port'], () => {
                            let
                                result  = {},
                                address = this.#server['address']()
                            ;
                            ///** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : address <${address['address']}>`);
                            ///** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : family  <${address['family']}>`);
                            ///** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : port    <${address['port']}>`);
                            ///** TODO:log */ console.log(`${new Date().toISOString()} : ${name} : server : ...listening`);
                            result['ts']     = hrt();
                            result['server'] = {
                                'agent':     "daps",
                                'address':   address['address'],
                                'family':    address['family'],
                                'port':      address['port'],
                                'listening': true
                            };
                            this.emit('listening', result);
                            resolve(result);
                        }); // service.listen
                    } // if
                } catch (jex) {
                    this.emit('errorOnListening', jex);
                } // try
            }); // rnP
        } // listen

    } // class DAPS

    daps = new DAPS(
        config,
        app
    );

    app.use((config['root'] || "/"), require(`./routes/route.js`)({
        'hrt':    hrt,
        'Helmut': Helmut,
        'agent':  daps,
        'config': config
    }));

    return daps;

};