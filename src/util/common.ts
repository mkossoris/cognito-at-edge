export const urlSafe = {
  /*
        Functions to translate base64-encoded strings, so they can be used:
        - in URL's without needing additional encoding
        - in OAuth2 PKCE verifier
        - in cookies (to be on the safe side, as = + / are in fact valid characters in cookies)
        stringify:
            use this on a base64-encoded string to translate = + / into replacement characters
        parse:
            use this on a string that was previously urlSafe.stringify'ed to return it to
            its prior pure-base64 form. Note that trailing = are not added, but NodeJS does not care
    */
  stringify: (b64encodedString: string) =>
    b64encodedString.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
  parse: (b64encodedString: string) =>
    b64encodedString.replace(/-/g, '+').replace(/_/g, '/'),
};
