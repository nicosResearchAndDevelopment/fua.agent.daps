const
    crypto      = require("crypto"),
    //jwt         = require("jsonwebtoken"),
    //{decodeProtectedHeader} = require('jose/util/decode_protected_header')
    {jwtVerify} = require('jose/jwt/verify'),
    {SignJWT}   = require('jose/jwt/sign')
;

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
                  'id':                   id,
                  'rootUri':              rootUri,
                  'domain':               domain,
                  'privateKey':           privateKey,
                  'jwt_header_kid':       jwt_header_kid_default = "default",
                  'jwt_header_algorithm': jwt_header_algorithm_default = "RS256",
                  //
                  'jwt_exp_offset':    jwt_exp_offset_default = 60, // REM in seconds
                  'jwt_payload_iss':   jwt_payload_iss_default,
                  'jwt_payload_aud':   jwt_payload_aud_default = "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL",
                  'jwt_payload_scope': jwt_payload_scope_default = ["ids_connector_attributes"]
              }) {

    let
        daps = {}
    ;

    if (new.target) {
        if (!id)
            throw new ErrorDapsIdIsMissing("id is missing");
        Object.defineProperties(daps, {
            id:          {
                value:      id,
                enumerable: true
            },
            domain:      {
                set: (dom) => {
                    if (!domain)
                        domain = dom;
                }
            },
            generateDAT: {
                value: async ({
                                  //'assertion':                req['body']['assertion'],
                                  'client_assertion':      client_assertion,
                                  'client_assertion_type': client_assertion_type,
                                  'grant_type':            grant_type,
                                  //
                                  'requesterPeerCertificate': requesterPeerCertificate,
                                  'jwt_header_kid':           jwt_header_kid,
                                  'jwt_header_algorithm':     jwt_header_algorithm,
                                  'jwt_exp_offset':           jwt_exp_offset, // REM in seconds
                                  'jwt_payload_aud':          jwt_payload_aud,
                                  'jwt_payload_nbf':          jwt_payload_nbf, // REM : in seconds
                                  'jwt_payload_scope':        jwt_payload_scope

                              }) => {

                    let
                        //decoded_token = jwt.decode(client_assertion),
                        tri           = client_assertion.split('.'),
                        decoded_token = JSON.parse(new Buffer(tri[1], 'base64').toString('ascii')),
                        user,
                        DAT           = undefined
                    ;

                    user                                 = await domain.users.get(`${rootUri}${decoded_token['sub'].replace(/:/g, '_')}`);
                    //const publicKey = crypto.createPublicKey(user['https://www.nicos-rd.com/model/daps#publicKey'][0]['@value']);
                    const
                        jwt_payload_sub                  = user['dapsm:skiaki'][0]['@value'],
                        jwt_payload_referringConnector   = user['dapsm:referringConnector'][0]['@value'],
                        jwt_payload_securityProfile      = user['dapsm:securityProfile'][0]['@value'],
                        jwt_payload_extendedGuarantee    = user['dapsm:extendedGuarantee'][0]['@value'],
                        jwt_payload_transportCertsSha256 = "mahlzeit", // TODO
                        jwt_payload_iat                  = Math.round((new Date).valueOf() / 1000),
                        verified                         = await jwtVerify(
                            client_assertion,
                            crypto.createPublicKey(user['dapsm:publicKey'][0]['@value'])
                        );

                    if (verified) {

                        let
                            jwt_header  = {
                                'typ': "JWT",
                                'kid': (jwt_header_kid || jwt_header_kid_default),
                                'alg': (jwt_header_algorithm || jwt_header_algorithm_default) // TODO: welcher ALGO?!
                            },
                            jwt_payload = {
                                '@context': "https://w3id.org/idsa/contexts/context.jsonld",
                                '@type':    "ids:DatPayload",
                                ///////////
                                "iss":                  jwt_payload_iss_default,
                                "sub":                  jwt_payload_sub,
                                "referringConnector":   jwt_payload_referringConnector,
                                "securityProfile":      jwt_payload_securityProfile,
                                "extendedGuarantee":    jwt_payload_extendedGuarantee,
                                "transportCertsSha256": [jwt_payload_transportCertsSha256],
                                "iat":                  jwt_payload_iat,
                                "exp":                  Math.round(jwt_payload_iat + (jwt_exp_offset || jwt_exp_offset_default)),
                                "aud":                  "https://w3id.org/idsa/code/IDS_CONNECTORS_ALL",
                                "nbf":                  (jwt_payload_nbf || jwt_payload_iat),
                                "scope":                (jwt_payload_scope || jwt_payload_scope_default)
                            }
                        ; // let

                        DAT = await new SignJWT(jwt_payload)
                            .setProtectedHeader(jwt_header)
                            .sign(privateKey);

                    } // if ()

                    return DAT;
                } // fn
            }, // generateDAT
            generateVC:  {
                value: async ({
                                  //'assertion':                req['body']['assertion'],
                                  'client_assertion':      client_assertion,
                                  'client_assertion_type': client_assertion_type,
                                  'grant_type':            grant_type,
                                  //
                                  'requesterPeerCertificate': requesterPeerCertificate
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