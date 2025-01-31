import axios from 'axios';
import { parse, stringify } from 'querystring';
import pino from 'pino';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { CloudFrontRequestEvent, CloudFrontRequestResult } from 'aws-lambda';
import {
  CookieAttributes,
  Cookies,
  SameSite,
  SAME_SITE_VALUES,
} from './util/cookie';

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
}

interface HandleRefreshAuthOptions {
  test: string;
}

interface HandleSignOutOptions {
  test: string;
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
      url: `https://${this._userPoolDomain}/oauth2/token`,
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
   * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
   * @param  {Object} tokens   Cognito User Pool tokens.
   * @param  {String} domain   Website domain.
   * @param  {String} location Path to redirection.
   * @return {Object} Lambda@Edge response.
   */
  private async _getRedirectResponse(tokens, domain, location) {
    const decoded = await this._jwtVerifier.verify(tokens.id_token);
    const username = decoded['cognito:username'];
    const usernameBase = `${this._cookieBase}.${username}`;
    const cookieAttributes: CookieAttributes = {
      domain: this._disableCookieDomain ? undefined : domain,
      expires: new Date(Date.now() + this._cookieExpirationDays * 864e5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
    };
    const cookies = [
      Cookies.serialize(
        `${usernameBase}.accessToken`,
        tokens.access_token,
        cookieAttributes
      ),
      Cookies.serialize(
        `${usernameBase}.idToken`,
        tokens.id_token,
        cookieAttributes
      ),
      Cookies.serialize(
        `${usernameBase}.refreshToken`,
        tokens.refresh_token,
        cookieAttributes
      ),
      Cookies.serialize(
        `${usernameBase}.tokenScopesString`,
        'phone email profile openid aws.cognito.signin.user.admin',
        cookieAttributes
      ),
      Cookies.serialize(
        `${this._cookieBase}.LastAuthUser`,
        username,
        cookieAttributes
      ),
    ];

    const response = {
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
   * Extract value of the authentication token from the request cookies.
   * @param  {Array}  cookieHeaders 'Cookie' request headers.
   * @return {String} Extracted access token. Throw if not found.
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
    // TODO: Protect from CSRF
    this._validateHandleCheckAuthOptions(options);
    this._logger.debug({ msg: 'Handling Lambda@Edge event', event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    let redirectURI = `https://${cfDomain}`;

    if (options?.signInRedirectPath) {
      redirectURI += options.signInRedirectPath;
    }

    try {
      const token = this._getIdTokenFromCookie(request.headers.cookie);
      this._logger.debug({ msg: 'Verifying token...', token });
      const user = await this._jwtVerifier.verify(token);
      this._logger.info({ msg: 'Forwarding request', path: request.uri, user });
      return request;
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code).then(
          (tokens) =>
            this._getRedirectResponse(tokens, cfDomain, requestParams.state)
        );
      } else {
        let redirectPath = request.uri;
        if (request.querystring && request.querystring !== '') {
          redirectPath += encodeURIComponent('?' + request.querystring);
        }
        const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${redirectPath}`;
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
    // TODO: Implement token refresh functionality
    return;
  }

  /**
   * Signs the user our of their current session. Removes both access token and refresh token
   * from cookies and invalidates the refresh token with Cognito.
   * @param event The CloudFront event.
   * @param options Options to configure the sign out behavior.
   * @returns
   */
  async handleSignOut(
    event: CloudFrontRequestEvent,
    options?: HandleSignOutOptions
  ) {
    // TODO: Implement sign out functionality
    return;
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
