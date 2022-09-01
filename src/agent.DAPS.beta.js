const
    crypto                          = require("crypto"),
    //jwt         = require("jsonwebtoken"),
    //{decodeProtectedHeader} = require('jose/util/decode_protected_header')
    //{jwtVerify} = require('jose/jwt/verify'),
    //{SignJWT}   = require('jose/jwt/sign'),
    {exportJWK, jwtVerify, SignJWT} = require('jose'),
    //
    util                            = require("@nrd/fua.core.util")
; // const

//const jose = require('jose');
//const parseJwk            = require('jose/JWKexport');

//region error
// TODO : better ERRORS :: code, etc.
class ErrorInstanceWithNew extends Error {
    constructor() {
        super(`[${timestamp()}] : fua.ids.agent.DAPS : DAPS :: has to bi instantiated with 'new'.`);
    }
}

class ErrorDapsIdIsMissing extends Error {
    constructor(message) {
        super(`[${timestamp()}] : fua.ids.agent.DAPS : DAPS :: ${message}`);
    }
}

//endregion error

//region fn
async function buildPublicKeySet(keys) {
    try {
        let result = {keys: []};
        for (const [key, value] of Object.entries(keys)) {
            let keyStoreEntry = await exportJWK(value.publicKey);
            keyStoreEntry.kid = key;
            //console.log(`${key}: ${value}`);
            result.keys.push(keyStoreEntry);
        } // for()
        return result;
    } catch (jex) {
        throw(jex);
    } // try
} // buildPublicKeySet()

//endregion fn

function DAPS({
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

    if (new.target) {

        let
            publicKeyStore = undefined, // REM : set at runtime
            daps           = {}
        ;
        if (!id)
            throw new ErrorDapsIdIsMissing("id is missing");

        (async () => {
                publicKeyStore = await buildPublicKeySet(keys)
            }
        )();

        Object.defineProperties(daps, {
            id:             {
                value:      id,
                enumerable: true
            },
            domain:         {
                set: (dom) => {
                    if (!domain)
                        domain = dom;
                }
            },
            jwks_path:      {
                get:           () => {
                    return jwks_path;
                }, enumerable: false
            },
            token_path:     {
                get:           () => {
                    return token_path;
                }, enumerable: false
            },
            vc_path:        {
                get:           () => {
                    return vc_path;
                }, enumerable: false
            },
            publicKeyStore: {
                get:           () => {
                    return publicKeyStore;
                }, enumerable: false
            },
            generateDAT:    {
                value: async ({
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

                              }) => {
                    try {
                        const
                            tri           = client_assertion.split('.'),
                            decoded_token = JSON.parse(new Buffer(tri[1], 'base64').toString('ascii')),
                            user          = await domain.getUserByAttribute('dapsm:skiaki', decoded_token['sub']),
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
                                    typ: jwt_header_typ,
                                    kid: (jwt_header_kid || jwt_header_kid_default),
                                    alg: (jwt_header_algorithm || jwt_header_algorithm_default) // TODO: welcher ALGO?!
                                },
                                jwt_payload = {
                                    '@context': "https://w3id.org/idsa/contexts/context.jsonld",
                                    '@type':    "ids:DatPayload",
                                    ///////////
                                    iss:                  jwt_payload_iss_default,
                                    sub:                  jwt_payload_sub,
                                    referringConnector:   jwt_payload_referringConnector,
                                    securityProfile:      jwt_payload_securityProfile,
                                    extendedGuarantee:    jwt_payload_extendedGuarantee,
                                    transportCertsSha256: [jwt_payload_transportCertsSha256],
                                    iat:                  jwt_payload_iat,
                                    exp:                  Math.trunc(jwt_payload_iat + (jwt_exp_offset || jwt_exp_offset_default)),
                                    aud:                  "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL",
                                    nbf:                  (jwt_payload_nbf || jwt_payload_iat),
                                    scope:                (jwt_payload_scope || jwt_payload_scope_default)
                                }
                            ; // let

                            if (tweak_DAT_custom_enabled && verified.payload.custom) {
                                jwt_payload.custom = verified.payload.custom;
                            } // if ()

                            if (tweak_DAT_generation && payload.tweak_dat) {
                                jwt_payload.iss = (payload.tweak_dat.iss || jwt_payload.iss);
                                jwt_payload.sub = (payload.tweak_dat.sub || jwt_payload.sub);
                                jwt_payload.sub = (payload.tweak_dat.referringConnector || jwt_payload.referringConnector);
                                jwt_payload.sub = (payload.tweak_dat.securityProfile || jwt_payload.securityProfile);
                                jwt_payload.sub = (payload.tweak_dat.extendedGuarantee || jwt_payload.extendedGuarantee);
                                jwt_payload.sub = (payload.tweak_dat.transportCertsSha256 || jwt_payload.transportCertsSha256);
                                jwt_payload.sub = (payload.tweak_dat.iat || jwt_payload.iat);
                                jwt_payload.sub = (payload.tweak_dat.exp || jwt_payload.exp);
                                jwt_payload.sub = (payload.tweak_dat.aud || jwt_payload.aud);
                                jwt_payload.sub = (payload.tweak_dat.nbf || jwt_payload.nbf);
                                jwt_payload.sub = (payload.tweak_dat.scope || jwt_payload.scope);
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
                    } catch (jex) {
                        throw(jex);
                    } // try
                } // fn
            }, // generateDAT
            generateVC:     {
                value: async ({
                                  //'assertion':                req['body']['assertion'],
                                  client_assertion:      client_assertion,
                                  client_assertion_type: client_assertion_type,
                                  grant_type:            grant_type,
                                  //
                                  requesterPeerCertificate: requesterPeerCertificate
                              }) => {

                    let
                        decoded_token = jwt['decode'](client_assertion),
                        user,
                        DAT
                    ;
                    user              = await domain.users.get(`${rootUri}${decoded_token['sub']}`);

                    return DAT;
                } // fn
            } // generateVC
        }); // Object.defineProperties()

        Object.freeze(daps);
        return daps;
    } else {
        throw new ErrorInstanceWithNew();
    } // if ()

} // DAPS()

Object.defineProperties(DAPS, {
    'id': {value: "http://www.nicos-rd.com/fua/ids#DAPS", enumerable: true}
});

exports.DAPS = DAPS;

// EOF