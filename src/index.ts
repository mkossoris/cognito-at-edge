import axios from 'axios';
import { parse, stringify } from 'querystring';
import pino from 'pino';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import {
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontRequestResult,
} from 'aws-lambda';
import {
  CookieAttributes,
  Cookies,
  SameSite,
  SAME_SITE_VALUES,
} from './util/cookie';
import { generateNonce } from './util/crypto';
import * as common from './util/common';

interface AuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  cookieExpirationDays?: number;
  disableCookieDomain?: boolean;
  httpOnly?: boolean;
  sameSite?: SameSite;
  logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
}

interface HandleCheckAuthOptions {
  /**
   * The path Cognito should redirect back to in your CloudFront distribution.
   * Must start with "/".
   * @default /
   */
  signInRedirectPath?: string;
  requestedRedirectUri?: string;
}

interface HandleRefreshAuthOptions {
  refreshRedirectPath?: string;
  requestedRedirectUri?: string;
}

interface HandleSignOutOptions {
  /**
   * The path Cognito should redirect back to in your CloudFront distribution.
   * Must start with "/".
   * @default /
   */
  signOutRedirectPath?: string;
  requestedRedirectUri?: string;
}

export class Authenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieExpirationDays: number;
  _disableCookieDomain: boolean;
  _httpOnly: boolean;
  _sameSite?: SameSite;
  _cookieBase: string;
  _userPoolTokenEndpoint: string;
  _userPoolRevokeEndpoint: string;
  _userPoolLogOutEndpoint: string;
  _logger;
  _jwtVerifier;

  constructor(params: AuthenticatorParams) {
    this._verifyParams(params);
    this._region = params.region;
    this._userPoolId = params.userPoolId;
    this._userPoolAppId = params.userPoolAppId;
    this._userPoolAppSecret = params.userPoolAppSecret;
    this._userPoolDomain = params.userPoolDomain;
    this._cookieExpirationDays = params.cookieExpirationDays || 365;
    this._disableCookieDomain =
      'disableCookieDomain' in params && params.disableCookieDomain === true;
    this._httpOnly = 'httpOnly' in params && params.httpOnly === true;
    this._sameSite = params.sameSite;
    this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
    this._userPoolTokenEndpoint = `https://${this._userPoolDomain}/oauth2/token`;
    this._userPoolRevokeEndpoint = `https://${this._userPoolDomain}/oauth2/revoke`;
    this._userPoolLogOutEndpoint = `https://${this._userPoolDomain}/logout`;
    this._logger = pino({
      level: params.logLevel || 'silent', // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
      userPoolId: params.userPoolId,
      clientId: params.userPoolAppId,
      tokenUse: 'id',
    });
  }

  parseCookie(cookieHeaders) {
    return Cookies.parse(cookieHeaders);
  }

  serializeCookie(name: string, value: string, attributes: CookieAttributes) {
    return Cookies.serialize(name, value, attributes);
  }

  /**
   * Verify that constructor parameters are corrects.
   * @param  {object} params constructor params
   * @return {void} throw an exception if params are incorects.
   */
  private _verifyParams(params) {
    if (typeof params !== 'object') {
      throw new Error('Expected params to be an object');
    }
    ['region', 'userPoolId', 'userPoolAppId', 'userPoolDomain'].forEach(
      (param) => {
        if (typeof params[param] !== 'string') {
          throw new Error(`Expected params.${param} to be a string`);
        }
      }
    );
    if (
      params.cookieExpirationDays &&
      typeof params.cookieExpirationDays !== 'number'
    ) {
      throw new Error('Expected params.cookieExpirationDays to be a number');
    }
    if (
      'disableCookieDomain' in params &&
      typeof params.disableCookieDomain !== 'boolean'
    ) {
      throw new Error('Expected params.disableCookieDomain to be a boolean');
    }
    if ('httpOnly' in params && typeof params.httpOnly !== 'boolean') {
      throw new Error('Expected params.httpOnly to be a boolean');
    }
    if ('sameSite' in params && !SAME_SITE_VALUES.includes(params.sameSite)) {
      throw new Error('Expected params.sameSite to be a Strict || Lax || None');
    }
  }

  private _validateNonce(request: CloudFrontRequest) {
    const state = parse(request.querystring).state;
    console.log('state is: ', state);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { nonce: currentNonce, requestedUri } = JSON.parse(
      Buffer.from(common.urlSafe.parse(state as string), 'base64').toString()
    );
    console.log('currentNonce is: ', currentNonce);
    const originalNonce = this._getNonceFromCookie(request.headers.cookie);
    console.log('originalNonce is: ', originalNonce);
    if (!currentNonce || !originalNonce || currentNonce !== originalNonce) {
      if (!originalNonce) {
        throw new Error(
          "Your browser didn't send the nonce cookie along, but it is required for security to prevent CSRF."
        );
      }
      throw new Error('Nonce mismatch');
    }
  }

  /**
   * Exchange authorization code for tokens.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} code        Authorization code.
   * @return {Promise} Authenticated user tokens.
   */
  private _fetchTokensFromCode(redirectURI, code) {
    const authorization =
      this._userPoolAppSecret &&
      Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString(
        'base64'
      );
    const request = {
      url: this._userPoolTokenEndpoint,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && { Authorization: `Basic ${authorization}` }),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: redirectURI,
      }),
    } as const;
    this._logger.debug({
      msg: 'Fetching tokens from grant code...',
      request,
      code,
    });
    return axios
      .request(request)
      .then((resp) => {
        this._logger.debug({ msg: 'Fetched tokens', tokens: resp.data });
        return resp.data;
      })
      .catch((err) => {
        this._logger.error({
          msg: 'Unable to fetch tokens from grant code',
          request,
          code,
        });
        throw err;
      });
  }

  /**
   * Exchange a refresh token for tokens.
   * @param  {String} grantType        grantType
   * @param  {String} refreshToken     refreshToken
   * @param  {String} redirectUrl      redirectUrl
   * @return {Promise} Authenticated user tokens.
   */
  private _exchangeRefreshTokenForTokens(
    grantType: string,
    refreshToken: string,
    redirectUrl: string
  ) {
    const authorization =
      this._userPoolAppSecret &&
      Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString(
        'base64'
      );
    this._logger.debug({
      msg: 'Authorization token is: ',
      authorization,
    });
    const request = {
      url: this._userPoolTokenEndpoint,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && { Authorization: `Basic ${authorization}` }),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        // The token endpoint returns refresh_token only when the grant_type is authorization_code.
        grant_type:
          grantType === 'refresh_token'
            ? 'refresh_token'
            : 'authorization_code',
        refresh_token: refreshToken,
        redirect_uri: redirectUrl,
      }),
    } as const;
    this._logger.debug({
      msg: 'Fetching new tokens using refresh token...',
      request,
    });
    //TODO: Consider adding logic when connecting with cognito apis using axios.
    return axios
      .request(request)
      .then((resp) => {
        this._logger.debug({ msg: 'Fetched new tokens', tokens: resp.data });
        return resp.data;
      })
      .catch((err) => {
        this._logger.error({
          msg: 'Unable to fetch new tokens using refresh tokens',
          request,
        });
        throw err;
      });
  }

  /**
   * Revoke tokens using refresh token from current session. Pass the refresh token that the client wants to revoke in the request body.
   * The request also revokes all access tokens that Amazon Cognito issued with this refresh token.
   * @param  {String} refreshToken     refreshToken
   * @return {Promise} void
   */
  private _revokeTokensUsingRefreshToken(refreshToken: string) {
    const authorization =
      this._userPoolAppSecret &&
      Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString(
        'base64'
      );
    this._logger.debug({
      msg: 'Authorization token is: ',
      authorization,
    });
    const request = {
      url: this._userPoolRevokeEndpoint,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(authorization && { Authorization: `Basic ${authorization}` }),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        token: refreshToken,
      }),
    } as const;
    this._logger.debug({
      msg: 'Revoking tokens using refresh token...',
      request,
    });
    return axios
      .request(request)
      .then((resp) => {
        this._logger.debug({ msg: 'Revoked new tokens', resp: resp.data });
      })
      .catch((err) => {
        this._logger.error({
          msg: 'Unable to revoke tokens using refresh tokens',
          request,
        });
        throw err;
      });
  }

  /**
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return {Object} Lambda@Edge response.
   */
  async getRedirectResponse(tokens, domain, location, nonce = undefined) {
    const decoded = await this._jwtVerifier.verify(tokens.id_token);
    const username = decoded['cognito:username'];
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieAttributesGeneral: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      expires: new Date(Date.now() + this._cookieExpirationDays * 864e5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
    };

    const nonceCookieAttributes: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      maxAge: 1800,
      secure: true,
      httpOnly: true,
      sameSite: this._sameSite,
    };

    const cookies = [
      Cookies.serialize(
        `${usernameBase}.accessToken`,
        tokens.access_token,
        cookieAttributesGeneral
      ),
      Cookies.serialize(
        `${usernameBase}.idToken`,
        tokens.id_token,
        cookieAttributesGeneral
      ),
      Cookies.serialize(
        `${usernameBase}.refreshToken`,
        tokens.refresh_token,
        cookieAttributesGeneral
      ),
      Cookies.serialize(
        `${usernameBase}.tokenScopesString`,
        'phone email profile openid aws.cognito.signin.user.admin',
        cookieAttributesGeneral
      ),
      Cookies.serialize(
        `${this._cookieBase}.LastAuthUser`,
        username,
        cookieAttributesGeneral
      ),
    ];

    if (nonce) {
      cookies.push(
        Cookies.serialize('cognito-at-edge-nonce', nonce, nonceCookieAttributes)
      );
    }

    const response = {
      // TODO: Consider replacing status code of all redirect responses with 307. Currently 302 for all.
      status: '302',
      headers: {
        location: [
          {
            key: 'Location',
            value: location,
          },
        ],
        'cache-control': [
          {
            key: 'Cache-Control',
            value: 'no-cache, no-store, max-age=0, must-revalidate',
          },
        ],
        pragma: [
          {
            key: 'Pragma',
            value: 'no-cache',
          },
        ],
        'set-cookie': cookies.map((c) => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Create a Lambda@Edge redirection response to clean up user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} redirectURI Path to redirection.
   * @return {Object} Lambda@Edge response.
   */
  //TODO: Clean up cookies by setting already expired date and replace value with empty field. Maybe only expired date is enough?
  private async _cleanUpCookieUsingToken(
    tokens,
    domain,
    redirectURI,
    state,
    nonce
  ) {
    const decoded = await this._jwtVerifier.verify(tokens.id_token);
    const username = decoded['cognito:username'];
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieAttributes: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      expires: new Date(0),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
    };
    const cookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, '', cookieAttributes),
      Cookies.serialize(`${usernameBase}.idToken`, '', cookieAttributes),
      Cookies.serialize(`${usernameBase}.refreshToken`, '', cookieAttributes),
      Cookies.serialize(
        `${usernameBase}.tokenScopesString`,
        '',
        cookieAttributes
      ),
      Cookies.serialize(
        `${this._cookieBase}.LastAuthUser`,
        '',
        cookieAttributes
      ),
      Cookies.serialize('cognito-at-edge-nonce', nonce, cookieAttributes),
    ];

    const response = {
      status: '302',
      headers: {
        location: [
          {
            key: 'Location',
            // value: `${this._userPoolLogOutEndpoint}?client_id=${this._userPoolAppId}&response_type=code&redirect_uri=${redirectURI}&state=${state}`,
            value: `${this._userPoolLogOutEndpoint}?client_id=${this._userPoolAppId}&logout_uri=${redirectURI}&state=${state}`,
          },
        ],
        'cache-control': [
          {
            key: 'Cache-Control',
            value: 'no-cache, no-store, max-age=0, must-revalidate',
          },
        ],
        pragma: [
          {
            key: 'Pragma',
            value: 'no-cache',
          },
        ],
        'set-cookie': cookies.map((c) => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted id token. Throw if not found.
   */
  private _cleanUpCookieUsingCookie(
    domain,
    redirectURI,
    cookieHeaders:
      | Array<{ key?: string | undefined; value: string }>
      | undefined,
    state,
    nonce
  ) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookieHeaders,
    });

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const tokenCookieNamePostfix = '.idToken';
    const usernameBase = cookieHeaders
      .flatMap((h) => Cookies.parse(h.value))
      .find(
        (c) =>
          c.name.startsWith(tokenCookieNamePrefix) &&
          c.name.endsWith(tokenCookieNamePostfix)
      )
      ?.name.replace('.idToken', '');

    const cookieAttributes: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      expires: new Date(0),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
    };
    const cookies = [
      Cookies.serialize(`${usernameBase}.accessToken`, '', cookieAttributes),
      Cookies.serialize(`${usernameBase}.idToken`, '', cookieAttributes),
      Cookies.serialize(`${usernameBase}.refreshToken`, '', cookieAttributes),
      Cookies.serialize(
        `${usernameBase}.tokenScopesString`,
        '',
        cookieAttributes
      ),
      Cookies.serialize(
        `${this._cookieBase}.LastAuthUser`,
        '',
        cookieAttributes
      ),
      Cookies.serialize('cognito-at-edge-nonce', nonce, cookieAttributes),
    ];

    const response = {
      status: '302',
      headers: {
        location: [
          {
            key: 'Location',
            // value: `${this._userPoolLogOutEndpoint}?client_id=${this._userPoolAppId}&response_type=code&redirect_uri=${redirectURI}&state=${state}`,
            value: `${this._userPoolLogOutEndpoint}?client_id=${this._userPoolAppId}&logout_uri=${redirectURI}&state=${state}`,
          },
        ],
        'cache-control': [
          {
            key: 'Cache-Control',
            value: 'no-cache, no-store, max-age=0, must-revalidate',
          },
        ],
        pragma: [
          {
            key: 'Pragma',
            value: 'no-cache',
          },
        ],
        'set-cookie': cookies.map((c) => ({ key: 'Set-Cookie', value: c })),
      },
    };

    this._logger.debug({ msg: 'Generated set-cookie response', response });

    return response;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted id token. Throw if not found.
   */
  private _getIdTokenFromCookie(
    cookieHeaders:
      | Array<{ key?: string | undefined; value: string }>
      | undefined
  ) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookieHeaders,
    });

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const tokenCookieNamePostfix = '.idToken';

    const cookies = cookieHeaders.flatMap((h) => Cookies.parse(h.value));
    const token = cookies.find(
      (c) =>
        c.name.startsWith(tokenCookieNamePrefix) &&
        c.name.endsWith(tokenCookieNamePostfix)
    )?.value;

    if (!token) {
      this._logger.debug("idToken wasn't present in request cookies");
      throw new Error("idToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found idToken in cookie', token });
    return token;
  }

  /**
   * Extract value of the refresh token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted refresh token. Throw if not found.
   */
  private _getRefreshTokenFromCookie(
    cookieHeaders:
      | Array<{ key?: string | undefined; value: string }>
      | undefined
  ) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookieHeaders,
    });

    const tokenCookieNamePrefix = `${this._cookieBase}.`;
    const tokenCookieNamePostfix = '.refreshToken';

    const cookies = cookieHeaders.flatMap((h) => Cookies.parse(h.value));
    const token = cookies.find(
      (c) =>
        c.name.startsWith(tokenCookieNamePrefix) &&
        c.name.endsWith(tokenCookieNamePostfix)
    )?.value;

    if (!token) {
      this._logger.debug("refreshToken wasn't present in request cookies");
      throw new Error("refreshToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found refreshToken in cookie', token });
    return token;
  }

  /**
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted id token. Throw if not found.
   */
  private _getTokensFromCookie(
    cookieHeaders:
      | Array<{ key?: string | undefined; value: string }>
      | undefined
  ) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookieHeaders,
    });

    const idTokenCookieNamePrefix = `${this._cookieBase}.`;
    const idTokenCookieNamePostfix = '.idToken';

    const cookies = cookieHeaders.flatMap((h) => Cookies.parse(h.value));
    const idToken = cookies.find(
      (c) =>
        c.name.startsWith(idTokenCookieNamePrefix) &&
        c.name.endsWith(idTokenCookieNamePostfix)
    )?.value;

    if (!idToken) {
      this._logger.debug("idToken wasn't present in request cookies");
      throw new Error("idToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found idToken in cookie', idToken });

    const accessTokenCookieNamePrefix = `${this._cookieBase}.`;
    const accessTokenCookieNamePostfix = '.accessToken';
    const accessToken = cookies.find(
      (c) =>
        c.name.startsWith(accessTokenCookieNamePrefix) &&
        c.name.endsWith(accessTokenCookieNamePostfix)
    )?.value;

    if (!accessToken) {
      this._logger.debug("accessToken wasn't present in request cookies");
      throw new Error("accessToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found accessToken in cookie', accessToken });

    const refreshTokenCookieNamePrefix = `${this._cookieBase}.`;
    const refreshTokenCookieNamePostfix = '.refreshToken';

    const refreshToken = cookies.find(
      (c) =>
        c.name.startsWith(refreshTokenCookieNamePrefix) &&
        c.name.endsWith(refreshTokenCookieNamePostfix)
    )?.value;

    if (!idToken) {
      this._logger.debug("refreshToken wasn't present in request cookies");
      throw new Error("refreshToken isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found refreshToken in cookie', refreshToken });

    return {
      id_token: idToken,
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  /**
   * Extract value of the nonce from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted nonce token. Throw if not found.
   */
  private _getNonceFromCookie(
    cookieHeaders:
      | Array<{ key?: string | undefined; value: string }>
      | undefined
  ) {
    if (!cookieHeaders) {
      this._logger.debug("Cookies weren't present in the request");
      throw new Error("Cookies weren't present in the request");
    }

    this._logger.debug({
      msg: 'Extracting authentication token from request cookie',
      cookieHeaders,
    });
    const nonce = cookieHeaders
      .flatMap((h) => Cookies.parse(h.value))
      .find((c) => c.name === 'cognito-at-edge-nonce').value;

    if (!nonce) {
      this._logger.debug("nonce wasn't present in request cookies");
      throw new Error("nonce isn't present in the request cookies");
    }

    this._logger.debug({ msg: 'Found nonce in cookie', nonce });
    return nonce;
  }

  private _validateHandleCheckAuthOptions(options?: HandleCheckAuthOptions) {
    if (!options) {
      return;
    }

    if (
      options.signInRedirectPath &&
      !options.signInRedirectPath.startsWith('/')
    ) {
      throw new Error(
        'HandleCheckAuthOptions.signInRedirectPath must start with a "/"'
      );
    }
    if (
      options.requestedRedirectUri &&
      !options.requestedRedirectUri.startsWith('https://')
    ) {
      throw new Error(
        'HandleCheckAuthOptions.requestedRedirectUri must start with a "https://"'
      );
    }
  }

  private _validateHandleRefreshOptions(options?: HandleRefreshAuthOptions) {
    if (!options) {
      return;
    }

    if (
      options.refreshRedirectPath &&
      !options.refreshRedirectPath.startsWith('/')
    ) {
      throw new Error(
        'HandleRefreshAuthOptions.signOutRedirectPath must start with a "/"'
      );
    }

    if (
      options.requestedRedirectUri &&
      !options.requestedRedirectUri.startsWith('https://')
    ) {
      throw new Error(
        'HandleRefreshAuthOptions.requestedRedirectUri must start with a "https://"'
      );
    }
  }

  private _validateHandleSignOutOptions(options?: HandleSignOutOptions) {
    if (!options) {
      return;
    }

    if (
      options.signOutRedirectPath &&
      !options.signOutRedirectPath.startsWith('/')
    ) {
      throw new Error(
        'HandleSignOutOptions.signOutRedirectPath must start with a "/"'
      );
    }

    if (
      options.requestedRedirectUri &&
      !options.requestedRedirectUri.startsWith('https://')
    ) {
      throw new Error(
        'HandleSignOutOptions.requestedRedirectUri must start with a "https://"'
      );
    }
  }

  /**
   * Checks if user is authorized, and does the following:
   *   * if authentication cookie is present and valid, forwards the request
   *   * if ?code<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param {CloudFrontRequestEvent}  event Lambda@Edge event.
   * @returns {Promise<CloudFrontRequestResult>} CloudFront response.
   */
  async handleCheckAuth(
    event: CloudFrontRequestEvent,
    options?: HandleCheckAuthOptions
  ) {
    this._validateHandleCheckAuthOptions(options);
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const request = event.Records[0].cf.request;
    const requestParams = parse(request.querystring);
    const requestedUri = `${request.uri}${
      request.querystring ? '?' + request.querystring : ''
    }`;
    const cfDomain = request.headers.host[0].value;
    let redirectURI = `https://${cfDomain}`;

    if (options?.signInRedirectPath) {
      redirectURI += options.signInRedirectPath;
    }

    try {
      this._validateNonce(request);
      const token = this._getIdTokenFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', token });
      const user = await this._jwtVerifier.verify(token);
      this._logger.info({ msg: 'Forwarding request', path: request.uri, user });

      if (options.requestedRedirectUri) {
        console.log(
          'Handle checkauth redirect when requestedRedirectUri is valid'
        );
        const nonce = generateNonce();
        console.log(
          'New nonce for check auth pass - forwarding request is: ',
          nonce
        );
        const uriUsedInState = encodeURIComponent(
          options?.requestedRedirectUri ?? requestedUri
        );
        console.log('uriUsedInState is: ', uriUsedInState);
        const state = common.urlSafe.stringify(
          Buffer.from(JSON.stringify({ nonce, uriUsedInState })).toString(
            'base64'
          )
        );
        console.log('state is: ', state);

        request.headers.cookie.flatMap((h) => Cookies.parse(h.value));
        const tokens = this._getTokensFromCookie(request.headers.cookie);

        redirectURI += '?' + `&state=${state}`;
        return this.getRedirectResponse(tokens, cfDomain, redirectURI, nonce);
      } else {
        return request;
      }
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      const nonce = generateNonce();
      const nonceCookieAttributes: CookieAttributes = {
        domain: this._disableCookieDomain ? undefined : cfDomain,
        maxAge: 1800,
        secure: true,
        httpOnly: true,
        sameSite: this._sameSite,
      };
      const nonceCookieValue = Cookies.serialize(
        'cognito-at-edge-nonce',
        nonce,
        nonceCookieAttributes
      );

      const uriUsedInState = encodeURIComponent(
        options?.requestedRedirectUri ?? requestedUri
      );
      console.log('uriUsedInState is: ', uriUsedInState);
      const state = common.urlSafe.stringify(
        Buffer.from(JSON.stringify({ nonce, uriUsedInState })).toString(
          'base64'
        )
      );
      console.log('state is: ', state);

      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code).then(
          (tokens) => {
            redirectURI += '?' + `&state=${state}`;

            return this.getRedirectResponse(
              tokens,
              cfDomain,
              redirectURI,
              nonce
            );
          }
        );
      } else {
        // /login and /oauth2/authorize are the same if not specifying an identity_provider or idp_identifier parameter in the URL
        // TODO: Consider replacing with stringifyQueryString for all url used in location
        const userPoolUrl = `https://${this._userPoolDomain}/login?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${state}`;
        this._logger.debug(
          `Redirecting user to Cognito User Pool URL ${userPoolUrl}`
        );
        return {
          status: '302',
          headers: {
            location: [
              {
                key: 'Location',
                value: userPoolUrl,
              },
            ],
            'cache-control': [
              {
                key: 'Cache-Control',
                value: 'no-cache, no-store, max-age=0, must-revalidate',
              },
            ],
            pragma: [
              {
                key: 'Pragma',
                value: 'no-cache',
              },
            ],
            'set-cookie': [{ key: 'set-cookie', value: nonceCookieValue }],
          },
        };
      }
    }
  }

  /**
   * Refreshes current user session with the refresh token included in the cookie.
   * If no token is present, returns a 400 error.
   * @param event The CloudFront event.
   * @param options Options to configure the refresh behavior.
   * @returns
   */
  async handleRefreshAuth(
    event: CloudFrontRequestEvent,
    options?: HandleRefreshAuthOptions
  ) {
    this._logger.debug({
      msg: 'Handling refresh token logic from Lambda@Edge event',
      event,
    });

    this._validateHandleRefreshOptions(options);

    const request = event.Records[0].cf.request;
    const requestParams = parse(request.querystring);
    this._logger.debug({ msg: 'request params', requestParams });
    const cfDomain = request.headers.host[0].value;
    let redirectURI = `https://${cfDomain}`;

    if (options?.refreshRedirectPath) {
      redirectURI += options.refreshRedirectPath;
    }

    const requestedUri = `${request.uri}${
      request.querystring ? '?' + request.querystring : ''
    }`;

    try {
      this._validateNonce(request);
      const refreshToken = this._getRefreshTokenFromCookie(
        request.headers.cookie
      );
      this._logger.debug({
        msg: 'Fetching new tokens using refresh token...',
        refreshToken,
      });

      const newTokens = await this._exchangeRefreshTokenForTokens(
        'refresh_token',
        refreshToken,
        redirectURI
      );
      newTokens.refresh_token = refreshToken;

      // prevent csrf, generate nonce
      const nonce = generateNonce();
      const uriUsedInState = encodeURIComponent(
        options?.requestedRedirectUri ?? requestedUri
      );
      console.log('uriUsedInState is: ', uriUsedInState);
      const state = common.urlSafe.stringify(
        Buffer.from(JSON.stringify({ nonce, uriUsedInState })).toString(
          'base64'
        )
      );
      console.log('state is: ', state);

      if (state && state !== '') {
        redirectURI += '?' + `state=${state}`;
      }
      return this.getRedirectResponse(newTokens, cfDomain, redirectURI, nonce);
      // return this.getRedirectResponse(newTokens, cfDomain, redirectURI, nonce);
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      const userPoolUrl = `https://${this._userPoolDomain}?error=unauthorized_client`;
      this._logger.debug(
        'Throw 401 - if the user never authenticated or refresh_token is revoked or expired'
      );
      return {
        status: '400',
        statusDescription: 'Bad Request',
        headers: {
          location: [
            {
              key: 'Location',
              value: userPoolUrl,
            },
          ],
          'cache-control': [
            {
              key: 'Cache-Control',
              value: 'no-cache, no-store, max-age=0, must-revalidate',
            },
          ],
          pragma: [
            {
              key: 'Pragma',
              value: 'no-cache',
            },
          ],
        },
      };
    }
  }

  /**
   * Signs the user out of their current session. Removes both access token and refresh token
   * from cookies and invalidates the refresh token with Cognito.
   * @param event The CloudFront event.
   * @param options Options to configure the sign out behavior.
   * @returns
   */
  async handleSignOut(
    event: CloudFrontRequestEvent,
    options?: HandleSignOutOptions
  ) {
    this._logger.debug({
      msg: 'Handling sign out logic from Lambda@Edge event',
      event,
    });

    this._validateHandleSignOutOptions(options);

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    this._logger.debug({ msg: 'request params', requestParams });
    const cfDomain = request.headers.host[0].value;
    let redirectURI = `https://${cfDomain}`;

    if (options?.signOutRedirectPath) {
      redirectURI += options.signOutRedirectPath;
    }

    const uriUsedInState = encodeURIComponent(
      options?.requestedRedirectUri ?? redirectURI
    );
    console.log('uriUsedInState is: ', uriUsedInState);

    const nonce = generateNonce();
    console.log('nonce is: ', nonce);
    const state = common.urlSafe.stringify(
      Buffer.from(JSON.stringify({ nonce, uriUsedInState })).toString('base64')
    );
    console.log('state is: ', state);

    try {
      this._validateNonce(request);
      const refreshToken = this._getRefreshTokenFromCookie(
        request.headers.cookie
      );
      this._logger.debug({
        msg: 'Revoking tokens using refresh token...',
        refreshToken,
      });
      return this._revokeTokensUsingRefreshToken(refreshToken).then(() => {
        return this._cleanUpCookieUsingCookie(
          cfDomain,
          options?.requestedRedirectUri ?? redirectURI,
          request.headers.cookie,
          state,
          nonce
        );
      });
    } catch (err) {
      this._logger.debug('Signout failed: %s', err);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code).then(
          (tokens) =>
            // this._cleanUpCookieUsingToken(tokens, cfDomain, redirectURI)
            this._cleanUpCookieUsingToken(
              tokens,
              cfDomain,
              options?.requestedRedirectUri ?? redirectURI,
              state,
              nonce
            )
        );
      } else {
        const userPoolUrl = `https://${this._userPoolDomain}?error=unauthorized_client`;
        this._logger.debug(
          'Throw 401 - if the user never authenticated or refresh_token is revoked or expired'
        );
        return {
          status: '401',
          statusDescription: 'Unauthorized',
          headers: {
            location: [
              {
                key: 'Location',
                value: userPoolUrl,
              },
            ],
            'cache-control': [
              {
                key: 'Cache-Control',
                value: 'no-cache, no-store, max-age=0, must-revalidate',
              },
            ],
            pragma: [
              {
                key: 'Pragma',
                value: 'no-cache',
              },
            ],
          },
        };
      }
    }
  }

  /**
   * Default handler Lambda@Edge event:
   *   * if authentication cookie is present and valid: forward the request
   *   * if ?code=<grant code> is present: set cookies with new tokens
   *   * else redirect to the Cognito UserPool to authenticate the user
   * @param  {Object}  event Lambda@Edge event.
   * @return {Promise} CloudFront response.
   * @deprecated Use `handleCheckAuth` instead.
   */
  async handle(
    event: CloudFrontRequestEvent
  ): Promise<CloudFrontRequestResult> {
    return await this.handleCheckAuth(event);
  }
}
