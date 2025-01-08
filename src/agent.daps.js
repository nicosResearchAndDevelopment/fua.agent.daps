const
    crypto               = require('crypto'),
    {jwtVerify, SignJWT} = require('jose'),
    util                 = require('@fua/core.util');

class DAPSAgent {

    static id = 'http://www.nicos-rd.com/fua/ids#DAPS';

    #id;
    #rootUri;
    #domain;
    #keys;
    #publicKey;
    #privateKey;
    #jwt_header_typ;
    #jwt_header_kid_default;
    #jwt_header_algorithm_default;
    #jwt_exp_offset_default;
    #jwt_payload_iss_default;
    #jwt_payload_aud_default;
    #jwt_payload_scope_default;
    #tweak_DAT_generation;
    #tweak_DAT_custom_enabled;
    #tweak_DAT_custom_max_size;
    #jwks_path;
    #token_path;
    #vc_path;

    #_nextDatRequestConfig;
    #publicKeyStore;

    constructor({
                    id:                   id,
                    rootUri:              rootUri,
                    domain:               domain,
                    keys:                 keys,
                    publicKey:            publicKey,
                    privateKey:           privateKey,
                    jwt_header_typ:       jwt_header_typ = "JWT",
                    jwt_header_kid:       jwt_header_kid_default = "default",
                    jwt_header_algorithm: jwt_header_algorithm_default = "RS256",
                    //
                    // TODO : what is the correct offset (DAPS.creterion) jwt_exp_offset:    jwt_exp_offset_default = 60, // REM in seconds
                    jwt_exp_offset:       jwt_exp_offset_default = 60, // REM in seconds
                    jwt_payload_iss:      jwt_payload_iss_default,
                    jwt_payload_aud:      jwt_payload_aud_default = "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL",
                    jwt_payload_scope:    jwt_payload_scope_default = ["ids_connector_attributes"],
                    tweak_DAT_generation: tweak_DAT_generation = false,
                    //
                    tweak_DAT_custom_enabled:  tweak_DAT_custom_enabled = false,
                    tweak_DAT_custom_max_size: tweak_DAT_custom_max_size = 1000, // REM : kB
                    //
                    jwks_path:  jwks_path = "/.well-known/jwks.json",
                    token_path: token_path = "/token",
                    vc_path:    vc_path = "/vc"
                }) {
        this.#id                           = id;
        this.#rootUri                      = rootUri;
        this.#domain                       = domain;
        this.#keys                         = keys;
        this.#publicKey                    = publicKey;
        this.#privateKey                   = privateKey;
        this.#jwt_header_typ               = jwt_header_typ;
        this.#jwt_header_kid_default       = jwt_header_kid_default;
        this.#jwt_header_algorithm_default = jwt_header_algorithm_default;
        this.#jwt_exp_offset_default       = jwt_exp_offset_default;
        this.#jwt_payload_iss_default      = jwt_payload_iss_default;
        this.#jwt_payload_aud_default      = jwt_payload_aud_default;
        this.#jwt_payload_scope_default    = jwt_payload_scope_default;
        this.#tweak_DAT_generation         = tweak_DAT_generation;
        this.#tweak_DAT_custom_enabled     = tweak_DAT_custom_enabled;
        this.#tweak_DAT_custom_max_size    = tweak_DAT_custom_max_size;
        this.#jwks_path                    = jwks_path;
        this.#token_path                   = token_path;
        this.#vc_path                      = vc_path;

        this.#_nextDatRequestConfig = undefined;
        this.#publicKeyStore        = {
            keys: Object.entries(keys).map(([key, value]) => Object.assign(
                value.publicKey.export({format: 'jwk'}),
                {kid: key}
            ))
        };
    }

    get id() {
        return this.#id;
    }

    get domain() {
        return this.#domain;
    }

    set domain(domain) {
        if (!this.#domain) this.#domain = dom;
    }

    get jwks_path() {
        return this.#jwks_path;
    }

    get token_path() {
        return this.#token_path;
    }

    get vc_path() {
        return this.#vc_path;
    }

    get publicKeyStore() {
        return this.#publicKeyStore;
    }

    get setNextDatRequestConfig() {
        return this.#_nextDatRequestConfig;
    }

    set setNextDatRequestConfig(config) {
        this.#_nextDatRequestConfig = config;
    }

    async generateDAT({
                          client_assertion:      client_assertion,
                          client_assertion_type: client_assertion_type,
                          grant_type:            grant_type,
                          scope:                 scope,
                          //
                          requesterPeerCertificate: requesterPeerCertificate,
                          jwt_header_kid:           jwt_header_kid,
                          jwt_header_algorithm:     jwt_header_algorithm,
                          jwt_exp_offset:           jwt_exp_offset, // REM in seconds
                          jwt_payload_aud:          jwt_payload_aud,
                          jwt_payload_nbf:          jwt_payload_nbf, // REM : in seconds
                          jwt_payload_scope:        jwt_payload_scope

                      }) {
        const
            tri           = client_assertion.split('.'),
            decoded_token = JSON.parse(new Buffer(tri[1], 'base64').toString('ascii')),
            user          = await this.#domain.getUserByAttribute('dapsm:skiaki', decoded_token['sub']),
            publicKey     = user.getLiteral('dapsm:publicKey').value
        ;
        let
            carrier       = {
                "access_token": "",
                "scope":        "ids_connector_attributes",
                "token_type":   "bearer",
                "expires_in":   "3600"
            },
            DAT
        ;

        const
            jwt_payload_sub                  = user.getLiteral('dapsm:skiaki').value,
            jwt_payload_referringConnector   = user.getLiteral('dapsm:referringConnector').value,
            jwt_payload_securityProfile      = user.getLiteral('dapsm:securityProfile').value,
            jwt_payload_extendedGuarantee    = user.getLiteral('dapsm:extendedGuarantee').value,
            // TODO : jwt_payload_transportCertsSha256 = "mahlzeit",
            jwt_payload_transportCertsSha256 = "mahlzeit",
            jwt_payload_iat                  = Math.trunc((new Date).valueOf() / 1000),
            verified                         = await jwtVerify(
                client_assertion,
                crypto.createPublicKey(publicKey)
            );

        if (verified) {

            let
                jwt_header  = {
                    typ: this.#jwt_header_typ,
                    kid: (jwt_header_kid || this.#jwt_header_kid_default),
                    alg: (jwt_header_algorithm || this.#jwt_header_algorithm_default) // TODO: welcher ALGO?!
                },
                jwt_payload = {
                    '@context': "https://w3id.org/idsa/contexts/context.jsonld",
                    '@type':    "ids:DatPayload",
                    ///////////
                    iss:                  this.#jwt_payload_iss_default,
                    sub:                  jwt_payload_sub,
                    referringConnector:   jwt_payload_referringConnector,
                    securityProfile:      jwt_payload_securityProfile,
                    extendedGuarantee:    jwt_payload_extendedGuarantee,
                    transportCertsSha256: [jwt_payload_transportCertsSha256],
                    iat:                  jwt_payload_iat,
                    exp:                  Math.trunc(jwt_payload_iat + (jwt_exp_offset || this.#jwt_exp_offset_default)),
                    aud:                  "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL",
                    nbf:                  (jwt_payload_nbf || jwt_payload_iat),
                    scope:                (jwt_payload_scope || this.#jwt_payload_scope_default)
                }
            ; // let

            if (this.#tweak_DAT_custom_enabled && verified.payload.custom) {
                jwt_payload.custom = verified.payload.custom;
            } // if ()

            // region testbed functions
            if (this.#_nextDatRequestConfig) {
                if (this.#_nextDatRequestConfig.address === "next") {
                    jwt_payload['@type']             = (this.#_nextDatRequestConfig.tweak_dat['@type'] || jwt_payload['@type']);
                    jwt_payload.iss                  = (this.#_nextDatRequestConfig.tweak_dat.iss || jwt_payload.iss);
                    jwt_payload.sub                  = (this.#_nextDatRequestConfig.tweak_dat.sub || jwt_payload.sub);
                    jwt_payload.referringConnector   = (this.#_nextDatRequestConfig.tweak_dat.referringConnector || jwt_payload.referringConnector);
                    jwt_payload.securityProfile      = (this.#_nextDatRequestConfig.tweak_dat.securityProfile || jwt_payload.securityProfile);
                    jwt_payload.extendedGuarantee    = (this.#_nextDatRequestConfig.tweak_dat.extendedGuarantee || jwt_payload.extendedGuarantee);
                    jwt_payload.transportCertsSha256 = (this.#_nextDatRequestConfig.tweak_dat.transportCertsSha256 || jwt_payload.transportCertsSha256);
                    jwt_payload.iat                  = (this.#_nextDatRequestConfig.tweak_dat.iat || jwt_payload.iat);
                    jwt_payload.exp                  = (this.#_nextDatRequestConfig.tweak_dat.exp || jwt_payload.exp);
                    jwt_payload.aud                  = (this.#_nextDatRequestConfig.tweak_dat.aud || jwt_payload.aud);
                    jwt_payload.nbf                  = (this.#_nextDatRequestConfig.tweak_dat.nbf || jwt_payload.nbf);
                    jwt_payload.scope                = (this.#_nextDatRequestConfig.tweak_dat.scope || jwt_payload.scope);
                    if (this.#_nextDatRequestConfig.once)
                        this.#_nextDatRequestConfig = undefined;
                } // if ()
            } // if ()
            // endregion testbed functions

            if (this.#tweak_DAT_generation && verified.payload.tweak_dat) {
                jwt_payload['@type']             = (verified.payload.tweak_dat['@type'] || jwt_payload['@type']);
                jwt_payload.iss                  = (verified.payload.tweak_dat.iss || jwt_payload.iss);
                jwt_payload.sub                  = (verified.payload.tweak_dat.sub || jwt_payload.sub);
                jwt_payload.referringConnector   = (verified.payload.tweak_dat.referringConnector || jwt_payload.referringConnector);
                jwt_payload.securityProfile      = (verified.payload.tweak_dat.securityProfile || jwt_payload.securityProfile);
                jwt_payload.extendedGuarantee    = (verified.payload.tweak_dat.extendedGuarantee || jwt_payload.extendedGuarantee);
                jwt_payload.transportCertsSha256 = (verified.payload.tweak_dat.transportCertsSha256 || jwt_payload.transportCertsSha256);
                jwt_payload.iat                  = (verified.payload.tweak_dat.iat || jwt_payload.iat);
                jwt_payload.exp                  = (verified.payload.tweak_dat.exp || jwt_payload.exp);
                jwt_payload.aud                  = (verified.payload.tweak_dat.aud || jwt_payload.aud);
                jwt_payload.nbf                  = (verified.payload.tweak_dat.nbf || jwt_payload.nbf);
                jwt_payload.scope                = (verified.payload.tweak_dat.scope || jwt_payload.scope);
            } // if ()

            DAT = await new SignJWT(jwt_payload)
                .setProtectedHeader(jwt_header)
                .sign(privateKey);

            carrier.access_token = DAT;
            carrier.expires_in   = jwt_payload.exp;
            carrier.scope        = jwt_payload.scope;

        } // if ()

        //return DAT;
        return carrier;
    }

    async generateVC({
                         //'assertion':                req['body']['assertion'],
                         client_assertion:      client_assertion,
                         client_assertion_type: client_assertion_type,
                         grant_type:            grant_type,
                         //
                         requesterPeerCertificate: requesterPeerCertificate
                     }) {
        let
            decoded_token = jwt['decode'](client_assertion),
            user,
            DAT
        ;
        user              = await domain.users.get(`${rootUri}${decoded_token['sub']}`);

        return DAT;
    }

}

module.exports = DAPSAgent;
