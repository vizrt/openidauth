## Open ID Authentication

**Authorization Middleware for Caddy**

This middleware implements an authorization layer for 
[Caddy](https://caddyserver.com) based one
[OpenID Connect](http://openid.net/connect/).  You can learn more about using
JWT in your application at [jwt.io](https://jwt.io). It validates tokens
against an external identity provider like Auth0, Google Identify Platform or
Azure Identity. Note that this middleware is limited to verify that the
provided token is valid and does not provide any features beyond that.

This middleware uses [Go
Openid](https://github.com/emanoelxavier/openid2go/tree/master/openid)
middleware that was written for the Go http server.

### Caddyfile Syntax
To set up the middleware you need to declare a `openid_auth` block and provide
information about the token issuer, client ids and which paths to protect:


```
openid_auth {
   issuer [issuer]
   clientid [clientid1]
   clientid [clientid2]
   path [path1]
   path [path2]
}
```
Issuer and at least one path is mandatory. If you do not specify any client
ids an empty list will be used.

Here is a full example configuration:

```
openid_auth {
   issuer https://accounts.google.com
   clientid 407408718192.apps.googleusercontent.com
   path /protected/ 
}
```

### Ways of passing a token for validation

There are two ways to pass the token for validation: (1) in the
`Authorization` header and (2) as a URL query parameter.  The middleware will
look in those places in the order listed and return `401` if it can't find
any token.

| Method               | Format                           |
| -------------------- | -------------------------------  |
| Authorization Header | `Authorization: Bearer <token>`  |
| URL Query Parameter  | `/protected?access_token=<token>`|

If no token is provided and the resource is protected the middleware
will insert a header: WWW-Authenticate: Bearer

### Enabling the middleware in Caddy ###
To enable this plugin run go get github.com/vizrt/openid_auth and import it
run [run.go](https://github.com/mholt/caddy/blob/master/caddy/caddymain/run.go)

```
import _ "github.com/vizrt/openid_auth"
```

You also need to insert a directive into plugins.go, eg before "jwt":

```
...
	"mime",
	"openiduath", // github.com/vizrt/openidauth
	"jwt",        // github.com/BTBurke/caddy-jwt
...
```
