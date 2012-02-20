signed-request
==============

A node.js signed string container. The form is basically:

```javascript
base64url(hmac256(string))&base64url(string)
```

That's a base64 URL encoded hmac256 hash of the string, followed by an ampersand `&`, followed by the base64 URL encoded string representation itself.
