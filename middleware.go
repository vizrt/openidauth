package openidauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go/request"
	"github.com/emanoelxavier/openid2go/openid"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// A function literal that fullfils the requirement of openId.PrivdersGetter
// It is used to ser up a new provider with the issuer and client ids from
// the configuration.
func getProviderFunc(issuer string, clientIds []string) openid.GetProvidersFunc {
	return func() ([]openid.Provider, error) {
		provider, err := openid.NewProvider(issuer, clientIds)
		if err != nil {
			return nil, err
		}
		return []openid.Provider{provider}, nil
	}
}

// This struct fullfuls the http.Handler interface that the openid.Authenticate
// function uses. It will be used to store the authenticate result
// so that we can read it back in this middleware and make decisions
// based on it.
//
type authenticationSuccessfull struct {
	Authenticated bool
}

// After successfull validation of a token this handler will be called
func (t *authenticationSuccessfull) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.Authenticated = true
}

// This error handler allows us to customize the response
func onAuthenticateFailed(e error, rw http.ResponseWriter, r *http.Request) bool {
	if verr, ok := e.(*openid.ValidationError); ok {
		httpStatus := verr.HTTPStatus

		switch verr.Code {
		case openid.ValidationErrorGetOpenIdConfigurationFailure:
			httpStatus = http.StatusServiceUnavailable
		case openid.ValidationErrorAuthorizationHeaderNotFound:
			// Istead of respoding with 400 Bad Response we want to say 401 Unauthorized
			// and indicate that this resource is protected and that you can authenticate
			// using a Bearer token. 400 Bad response was set in the validation error from
			// the underlaying openid code.
			httpStatus = http.StatusUnauthorized
			rw.Header().Add("WWW-Authenticate", "Bearer")
		}
		http.Error(rw, verr.Message, httpStatus)
	} else {
		// Not supposed to happen, but if it does we will have some information to go on.
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(rw, e.Error())
	}

	// We have handled the error, so return true to halt the execution so that
	// the next handler is not going to be called.
	return /*halt=*/ true
}

// ServeHTTP is the main entrypoint for the middleware during execution.
func (h auth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	// To support having the token as a query paramter we extract it here and
	// insert it as an Authorization header so that the underlaying code
	// (which only can use the Authorization header) works.
	a := request.ArgumentExtractor{"access_token"}
	token, err := a.ExtractToken(r)
	if err == nil {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	// If the requested path mathces a path in the configuration, validate the JWT
	for _, p := range h.Paths {
		if !httpserver.Path(r.URL.Path).Matches(p) {
			continue
		}

		// Path matches. Authenticate
		authHandler := authenticationSuccessfull{false}
		openid.Authenticate(h.Configuration, &authHandler).ServeHTTP(w, r)
		if !authHandler.Authenticated {
			// The success handler was not called, so it failed.
			// We return 0 to indicate that the response has already been written.
			return 0, errors.New("Token verification failed")
		}
		// Authenticated so call next middleware
		return h.Next.ServeHTTP(w, r)
	}

	// pass request if no paths protected with JWT or the code above falls through
	return h.Next.ServeHTTP(w, r)
}
