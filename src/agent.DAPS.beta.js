const
    crypto      = require("crypto"),
    //jwt         = require("jsonwebtoken"),
    //{decodeProtectedHeader} = require('jose/util/decode_protected_header')
    {jwtVerify} = require('jose/jwt/verify'),
    {SignJWT}   = require('jose/jwt/sign'),
    //
    util        = require("@nrd/fua.core.util"),
    AgentJOSE   = require('@nrd/fua.agent.jose')
; // const

//const jose = require('jose');
//const parseJwk            = require('jose/JWKexport');

//region error
class ErrorDapsIdIsMissing extends Error {
    constructor(message) {
        super(`[${timestamp()}] : fua.ids.agent.DAPS : DAPS :: ${message}`);
    }
}

//endregion error

//region fn
//function timestamp() {
//    return (new Date).toISOString();
//}
//endregion fn

function DAPS({
                  id:                   id,
                  rootUri:              rootUri,
                  domain:               domain,
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
                  jwks_path:  jwks_path = "/.well-known/jwks.json",
                  token_path: token_path = "/token",
                  vc_path:    vc_path = "/vc"
              }) {

    let
        //that = AgentJOSE,
        jwsk = {
            "keys": [
                {
                    "kid": "default",
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "x5c": [
                        ""
                    ],
                    "n":   "",
                    "e":   "",
                    "x5t": ""
                }
            ]
        },
        daps = {}
    ;

    //jwsk = exportJWK(publicKey);
        //debugger;

    if (new.target) {
        if (!id)
            throw new ErrorDapsIdIsMissing("id is missing");
        Object.defineProperties(daps, {
            id:         {
                value:      id,
                enumerable: true
            },
            domain:     {
                set: (dom) => {
                    if (!domain)
                        domain = dom;
                }
            },
            jwks_path:  {
                get:           () => {
                    return jwks_path;
                }, enumerable: false
            },
            token_path: {
                get:           () => {
                    return token_path;
                }, enumerable: false
            },
            vc_path:    {
                get:           () => {
                    return vc_path;
                }, enumerable: false
            },

            jwks:        {
                get:           () => {
                    return jwsk;
                }, enumerable: false
            },
            generateDAT: {
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
                            user          = await domain.users.getByAttr('dapsm:skiaki', decoded_token['sub']),
                            publicKey     = user.getLiteral('dapsm:publicKey').value
                        ;
                        let
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

                            if (tweak_DAT_generation && payload.tweak_dat) {
                                jwt_payload.iss = (payload.tweak_dat.iss || jwt_payload.iss);
                                jwt_payload.sub = (payload.tweak_dat.sub || jwt_payload.sub);
                                jwt_payload.sub = (payload.tweak_dat.referringConnector || referringConnector.sub);
                                jwt_payload.sub = (payload.tweak_dat.securityProfile || referringConnector.securityProfile);
                                jwt_payload.sub = (payload.tweak_dat.extendedGuarantee || referringConnector.extendedGuarantee);
                                jwt_payload.sub = (payload.tweak_dat.transportCertsSha256 || referringConnector.transportCertsSha256);
                                jwt_payload.sub = (payload.tweak_dat.iat || referringConnector.iat);
                                jwt_payload.sub = (payload.tweak_dat.exp || referringConnector.exp);
                                jwt_payload.sub = (payload.tweak_dat.aud || referringConnector.aud);
                                jwt_payload.sub = (payload.tweak_dat.nbf || referringConnector.nbf);
                                jwt_payload.sub = (payload.tweak_dat.scope || referringConnector.scope);
                            } // if ()

                            DAT = await new SignJWT(jwt_payload)
                                .setProtectedHeader(jwt_header)
                                .sign(privateKey);

                        } // if ()

                        return DAT;
                    } catch (jex) {
                        throw(jex);
                    } // try
                } // fn
            }, // generateDAT
            generateVC:  {
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
    } // if ()
    Object.freeze(daps);
    return daps;
} // DAPS()

Object.defineProperties(DAPS, {
    'id': {value: "http://www.nicos-rd.com/fua/ids#DAPS", enumerable: true}
});

exports.DAPS = DAPS;

// EOF