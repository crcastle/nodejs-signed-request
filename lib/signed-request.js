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

module.exports.getSignature = function(payload, secret) {
  if (!secret) throw Error('A secret must be provided.');
  //if ('issued_at' in data) throw Error('data must not contain an issued_at.')

  // make a clone of the string
  payload = payload + "";

  var hmac = crypto.createHmac(ALGORITHM, secret).update(b64url.encode(payload)),
      sig = b64url.safe(hmac.digest('base64'));

  return sig;
};

module.exports.isValidSignature = function(sig, payload, secret) {
  if (!sig) throw Error('A signature must be provided.');
  if (!secret) throw Error('A secret must be provided.');

  //if (ttl === undefined) throw Error('A ttl in seconds must be provided.')

  var hmac = crypto.createHmac(ALGORITHM, secret).update(b64url.encode(payload)),
      expectedSig = b64url.safe(hmac.digest('base64'));

  return (sig == expectedSig);
};
