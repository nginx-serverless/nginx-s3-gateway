/*
 *  Copyright 2023 F5, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import utils from "./utils.js";

const fs = require('fs');

/**
 * Constant checksum for an empty HTTP body.
 * @type {string}
 */
const EMPTY_PAYLOAD_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';


/**
 * Create HTTP Authorization header for authenticating with an AWS compatible
 * v4 API.
 *
 * @param r {Request} HTTP request object
 * @param timestamp {Date} timestamp associated with request (must fall within a skew)
 * @param region {string} API region associated with request
 * @param service {string} service code (for example, s3, lambda)
 * @param uri {string} The URI-encoded version of the absolute path component URL to create a canonical request
 * @param queryParams {string} The URL-encoded query string parameters to create a canonical request
 * @param host {string} HTTP host header value
 * @param credentials {object} Credential object with AWS credentials in it (AccessKeyId, SecretAccessKey, SessionToken)
 * @returns {string} HTTP Authorization header value
 */
function signatureV4(r, timestamp, region, service, uri, queryParams, host, credentials) {
    const eightDigitDate = utils.getEightDigitDate(timestamp);
    const amzDatetime = utils.getAmzDatetime(timestamp, eightDigitDate);
    const canonicalRequest = _buildCanonicalRequest(
        r.method, uri, queryParams, host, amzDatetime, credentials.sessionToken);
    const signature = _buildSignatureV4(r, amzDatetime, eightDigitDate, credentials, bucket, region, server);
    const authHeader = 'AWS4-HMAC-SHA256 Credential='
        .concat(credentials.accessKeyId, '/', eightDigitDate, '/', region, '/', service, '/aws4_request,',
            'SignedHeaders=', signedHeaders(credentials.sessionToken), ',Signature=', signature);

    utils.debug_log(r, 'AWS v4 Auth header: [' + authHeader + ']');

    return authHeader;
}

/**
 * Creates a canonical request that will later be signed
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html | Creating a Canonical Request}
 * @param method {string} HTTP method
 * @param uri {string} URI associated with request
 * @param queryParams {string} query parameters associated with request
 * @param host {string} HTTP Host header value
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @returns {string} string with concatenated request parameters
 * @private
 */
function _buildCanonicalRequest(method, uri, queryParams, host, amzDatetime, sessionToken) {
    let canonicalHeaders = 'host:' + host + '\n' +
        'x-amz-content-sha256:' + EMPTY_PAYLOAD_HASH + '\n' +
        'x-amz-date:' + amzDatetime + '\n';

    if (sessionToken) {
        canonicalHeaders += 'x-amz-security-token:' + sessionToken + '\n'
    }

    let canonicalRequest = method + '\n';
    canonicalRequest += uri + '\n';
    canonicalRequest += queryParams + '\n';
    canonicalRequest += canonicalHeaders + '\n';
    canonicalRequest += signedHeaders(sessionToken) + '\n';
    canonicalRequest += EMPTY_PAYLOAD_HASH;

    return canonicalRequest;
}

/**
 * Creates a signature for use authenticating against an AWS compatible API.
 *
 * @see {@link https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html | AWS V4 Signing Process}
 * @param r {Request} HTTP request object
 * @param amzDatetime {string} ISO8601 timestamp string to sign request with
 * @param eightDigitDate {string} date in the form of 'YYYYMMDD'
 * @param bucket {string} S3 bucket associated with request
 * @param region {string} API region associated with request
 * @returns {string} hex encoded hash of signature HMAC value
 * @private
 */
function _buildSignatureV4(r, amzDatetime, eightDigitDate, creds, bucket, region, server) {
    let host = server;
    if (S3_STYLE === 'virtual' || S3_STYLE === 'default' || S3_STYLE === undefined) {
        host = bucket + '.' + host;
    }
    const method = r.method;
    const baseUri = s3BaseUri(r);
    const queryParams = _s3DirQueryParams(r.variables.uri_path, method);
    let uri;
    if (queryParams.length > 0) {
        if (baseUri.length > 0) {
            uri = baseUri;
        } else {
            uri = '/';
        }
    } else {
        uri = s3uri(r);
    }

    const canonicalRequest = _buildCanonicalRequest(method, uri, queryParams, host, amzDatetime, creds.sessionToken);

    utils.debug_log(r, 'AWS v4 Auth Canonical Request: [' + canonicalRequest + ']');

    const canonicalRequestHash = mod_hmac.createHash('sha256')
        .update(canonicalRequest)
        .digest('hex');

    utils.debug_log(r, 'AWS v4 Auth Canonical Request Hash: [' + canonicalRequestHash + ']');

    const stringToSign = _buildStringToSign(amzDatetime, eightDigitDate, region, canonicalRequestHash);

    utils.debug_log(r, 'AWS v4 Auth Signing String: [' + stringToSign + ']');

    let kSigningHash;

    /* If we have a keyval zone and key defined for caching the signing key hash,
     * then signing key caching will be enabled. By caching signing keys we can
     * accelerate the signing process because we will have four less HMAC
     * operations that have to be performed per incoming request. The signing
     * key expires every day, so our cache key can persist for 24 hours safely.
     */
    if ("variables" in r && r.variables.cache_signing_key_enabled == 1) {
        // cached value is in the format: [eightDigitDate]:[signingKeyHash]
        const cached = "signing_key_hash" in r.variables ? r.variables.signing_key_hash : "";
        const fields = _splitCachedValues(cached);
        const cachedEightDigitDate = fields[0];
        const cacheIsValid = fields.length === 2 && eightDigitDate === cachedEightDigitDate;

        // If true, use cached value
        if (cacheIsValid) {
            utils.debug_log(r, 'AWS v4 Using cached Signing Key Hash');
            /* We are forced to JSON encode the string returned from the HMAC
             * operation because it is in a very specific format that include
             * binary data and in order to preserve that data when persisting
             * we encode it as JSON. By doing so we can gracefully decode it
             * when reading from the cache. */
            kSigningHash = Buffer.from(JSON.parse(fields[1]));
        // Otherwise, generate a new signing key hash and store it in the cache
        } else {
            kSigningHash = _buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, SERVICE, region);
            utils.debug_log(r, 'Writing key: ' + eightDigitDate + ':' + kSigningHash.toString('hex'));
            r.variables.signing_key_hash = eightDigitDate + ':' + JSON.stringify(kSigningHash);
        }
    // Otherwise, don't use caching at all (like when we are using NGINX OSS)
    } else {
        kSigningHash = _buildSigningKeyHash(creds.secretAccessKey, eightDigitDate, SERVICE, region);
    }

    utils.debug_log(r, 'AWS v4 Signing Key Hash: [' + kSigningHash.toString('hex') + ']');

    const signature = mod_hmac.createHmac('sha256', kSigningHash)
        .update(stringToSign).digest('hex');

    utils.debug_log(r, 'AWS v4 Authorization Header: [' + signature + ']');

    return signature;
}



/**
 * Get the current session token from either the instance profile credential 
 * cache or environment variables.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {string} current session token or empty string
 */
function sessionToken(r) {
    const credentials = readCredentials(r);
    if (credentials.sessionToken) {
        return credentials.sessionToken;
    }
    return '';
}

/**
 * Get the instance profile credentials needed to authenticated against S3 from
 * a backend cache. If the credentials cannot be found, then return undefined.
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string|null), expiration: (string|null)}} AWS instance profile credentials or undefined
 */
function readCredentials(r) {
    // TODO: Change the generic constants naming for multiple AWS services.
    if ('S3_ACCESS_KEY_ID' in process.env && 'S3_SECRET_KEY' in process.env) {
        const sessionToken = 'S3_SESSION_TOKEN' in process.env ?
                              process.env['S3_SESSION_TOKEN'] : null;
        return {
            accessKeyId: process.env['S3_ACCESS_KEY_ID'],
            secretAccessKey: process.env['S3_SECRET_KEY'],
            sessionToken: sessionToken,
            expiration: null
        };
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        return _readCredentialsFromKeyValStore(r);
    } else {
        return _readCredentialsFromFile();
    }
}

/**
 * Read credentials from the NGINX Keyval store. If it is not found, then
 * return undefined.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromKeyValStore(r) {
    const cached = r.variables.instance_credential_json;

    if (!cached) {
        return undefined;
    }

    try {
        return JSON.parse(cached);
    } catch (e) {
        utils.debug_log(r, `Error parsing JSON value from r.variables.instance_credential_json: ${e}`);
        return undefined;
    }
}

/**
 * Read the contents of the credentials file into memory. If it is not
 * found, then return undefined.
 *
 * @returns {undefined|{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials or undefined
 * @private
 */
function _readCredentialsFromFile() {
    const credsFilePath = _credentialsTempFile();

    try {
        const creds = fs.readFileSync(credsFilePath);
        return JSON.parse(creds);
    } catch (e) {
        /* Do not throw an exception in the case of when the
           credentials file path is invalid in order to signal to
           the caller that such a file has not been created yet. */
        if (e.code === 'ENOENT') {
            return undefined;
        }
        throw e;
    }
}

/**
 * Returns the path to the credentials temporary cache file.
 *
 * @returns {string} path on the file system to credentials cache file
 * @private
 */
function _credentialsTempFile() {
    if (process.env['S3_CREDENTIALS_TEMP_FILE']) {
        return process.env['S3_CREDENTIALS_TEMP_FILE'];
    }
    if (process.env['TMPDIR']) {
        return `${process.env['TMPDIR']}/credentials.json`
    }

    return '/tmp/credentials.json';
}

/**
 * Write the instance profile credentials to a caching backend.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 */
function writeCredentials(r, credentials) {
    /* Do not bother writing credentials if we are running in a mode where we
       do not need instance credentials. */
    if (process.env['S3_ACCESS_KEY_ID'] && process.env['S3_SECRET_KEY']) {
        return;
    }

    if (!credentials) {
        throw `Cannot write invalid credentials: ${JSON.stringify(credentials)}`;
    }

    if ("variables" in r && r.variables.cache_instance_credentials_enabled == 1) {
        _writeCredentialsToKeyValStore(r, credentials);
    } else {
        _writeCredentialsToFile(credentials);
    }
}

/**
 * Write the instance profile credentials to the NGINX Keyval store.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToKeyValStore(r, credentials) {
    r.variables.instance_credential_json = JSON.stringify(credentials);
}

/**
 * Write the instance profile credentials to a file on the file system. This
 * file will be quite small and should end up in the file cache relatively
 * quickly if it is repeatedly read.
 *
 * @param r {Request} HTTP request object (not used, but required for NGINX configuration)
 * @param credentials {{accessKeyId: (string), secretAccessKey: (string), sessionToken: (string), expiration: (string)}} AWS instance profile credentials
 * @private
 */
function _writeCredentialsToFile(credentials) {
    fs.writeFileSync(_credentialsTempFile(), JSON.stringify(credentials));
}

export default {
    readCredentials,
    sessionToken,
    signatureV4,
    writeCredentials
}
