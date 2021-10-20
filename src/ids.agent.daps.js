const {EventEmitter} = require('events');

class Daps extends EventEmitter {
    #id        = "agent/daps/";
    #daps_host = "";

    #publicKey = undefined; // !!!

    //region DAT
    #default_DAT_payload_context             = "ids:DatRequestToken";
    #default_DAT_payload_expiration_duration = (24 * 60 * 60); // REM : one day in seconds
    #default_DAT_payload_scope               = undefined;

    //endregion DAT

    constructor({
                    '@id':       id = undefined,
                    'daps_host': daps_host = undefined,
                    'publicKey': publicKey,
                    //
                    'DAT_payload_context':             DAT_payload_context = undefined,
                    'DAT_payload_expiration_duration': DAT_payload_expiration_duration = undefined,
                    'DAT_payload_scope':               DAT_payload_scope = undefined

                }) {

        super(); // REM : EventEmitter

        this.#id        = (id || this.#id);
        this.#daps_host = daps_host; // REM: payload.iss

        if ((!this.#daps_host) || (this.#daps_host === ""))
            throw (new Error(`Daps agent : 'daps_host' is missing.`));

        this.#default_DAT_payload_context             = (DAT_payload_context || this.#default_DAT_payload_context);
        this.#default_DAT_payload_expiration_duration = (DAT_payload_expiration_duration || this.#default_DAT_payload_expiration_duration);
        this.#default_DAT_payload_scope               = (DAT_payload_scope || this.#default_DAT_payload_scope);

        Object.defineProperties(this.token, {
            '@id': {value: `${this.#id}token`}
        });

    } // constructor

    get ['id']() {
        return this.#id;
    }

    async token({
                    'grant_type':            grant_type,
                    'client_assertion_type': client_assertion_type,
                    'client_assertion':      client_assertion,
                    'scope':                 scope,
                    'subject':               subject, // REM: header.sub
                    'experation':            experation = undefined, // REM: header.exp
                    'valid_not_before':      valid_not_before = undefined, // REM: header.nbf
                    'audience':              audience // REM: header.aud
                }) {
        try {
            let
                now_in_seconds = Math.round(Date.now() / 1000), // REM: payload.iat
                header         = {
                    'typ': undefined,
                    'kid': undefined,
                    'alg': undefined
                },
                payload        = {
                    '@context': this.#default_DAT_payload_context,
                    '@type':    "ids:DatRequestToken",
                    'iss':      this.#daps_host,
                    'iat':      now_in_seconds,
                    'exp':      (now_in_seconds + this.#default_DAT_payload_expiration_duration),
                    'nbf':      (valid_not_before + now_in_seconds)
                }
            ;
            if (audience)
                payload['aud'] = audience;
            this['emit']("token.result", {
                'header':  header,
                'payload': payload
            });
            return DAT;
        } catch (jex) {
            throw jex;
        } // try
    } // token()

} // class Daps

module.exports = Daps;
//
//exprorts.Daps  = Daps;
//exprorts.agent = agent;
//
//const
//    Daps = require('ids.agent.daps'),
//    daps = new Daps({})
//;
