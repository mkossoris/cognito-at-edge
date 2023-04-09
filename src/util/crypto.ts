import { createHash, randomBytes } from 'crypto';

// Allowed characters per https://tools.ietf.org/html/rfc7636#section-4.1
const SECRET_ALLOWED_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const PKCE_LENGTH = 43; // The code verifier should be a high-entropy cryptographic random string with a minimum of 43 characters and a maximum of 128 characters.
const NONCE_LENGTH = 16; // TODO: what is an appropriate length value?

// turning token into JSON string from binary
export function decodeToken(jwt: string) {
  const tokenBody = jwt.split('.')[1];
  const decodableTokenBody = tokenBody.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(decodableTokenBody, 'base64').toString());
}

export const generatePkceVerifier = () => {
  const pkce = [...new Array(PKCE_LENGTH)]
    .map(() => randomChoiceFromIndexable(SECRET_ALLOWED_CHARS))
    .join('');
  return {
    pkce,
    pkceHash: createHash('sha256')
      .update(pkce, 'utf8')
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_'),
  };
};

export const generateNonce = () => {
  return [...new Array(NONCE_LENGTH)]
    .map(() => randomChoiceFromIndexable(SECRET_ALLOWED_CHARS))
    .join('');
};

const randomChoiceFromIndexable = (indexable: string) => {
  if (indexable.length > 256) {
    throw new Error(`indexable is too large: ${indexable.length}`);
  }
  const chunks = Math.floor(256 / indexable.length);
  let randomNumber: number;
  do {
    randomNumber = randomBytes(1)[0];
  } while (randomNumber >= indexable.length * chunks);
  const index = randomNumber % indexable.length;
  return indexable[index];
};
