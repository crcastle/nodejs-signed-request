var signedRequest = require('signed-request'),
    assert = require('assert');

/*
function isInt(n) {
  return typeof n == 'number' && n % 1 === 0;
}
*/

exports['sign and verify'] = function() {
  var data = 'this is a secret message!',
      secret = 'abcd',
      signature = signedRequest.getSignature(data, secret),
      isValid = signedRequest.isValidSignature(signature, data, secret);
  assert(isValid, 'expect the answer.');
};

/*
exports['issued_at is an integer'] = function() {
  var data = { answer: 42 },
      secret = 'abcd',
      signed = signedRequest.stringify(data, secret),
      parsed = signedRequest.parse(signed, secret, 1000);
  assert(isInt(parsed.issued_at));
};
*/
