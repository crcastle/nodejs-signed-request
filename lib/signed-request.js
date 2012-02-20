var b64url = require('b64url'),
    crypto = require('crypto'),
    makeError = require('makeerror'),
    ALGORITHM = 'sha256';

exports.Error = makeError('SignedRequestError');

exports.InvalidSignatureError = makeError(
  'InvalidSignatureError',
  'The signature was invalid.',
  { proto: exports.Error() }
);

exports.ExpiredError = makeError(
  'ExpiredError',
  'The signed request has expired. Was issued at: {issuedAt}.',
  { proto: exports.Error() }
);

module.exports.stringify = function(data, secret) {
  if (!secret) throw Error('A secret must be provided.');
  //if ('issued_at' in data) throw Error('data must not contain an issued_at.')

  data = data + "";

  var hmac = crypto.createHmac(ALGORITHM, secret).update(b64url.encode(data)),
      sig = b64url.safe(hmac.digest('base64'));

  return sig + '&' + data;
};

module.exports.parse = function(raw, secret) {
  if (!secret) throw Error('A secret must be provided.');
  //if (ttl === undefined) throw Error('A ttl in seconds must be provided.')

  var ampPos = raw.indexOf('&'),
      sig = raw.substr(0, ampPos),
      payload = raw.substr(ampPos + 1),
      hmac = crypto.createHmac(ALGORITHM, secret).update(b64url.encode(payload)),
      expectedSig = b64url.safe(hmac.digest('base64'));

  if (sig !== expectedSig) throw exports.InvalidSignatureError();

  var data = payload;

  return data;
};
