package openidauth

import (
	"errors"
	"fmt"

	"github.com/emanoelxavier/openid2go/openid"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type auth struct {
	Configuration *openid.Configuration
	Paths         []string
	Next          httpserver.Handler
}

func init() {
	caddy.RegisterPlugin("openidauth", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// Setup sets up the middleware
func Setup(c *caddy.Controller) error {
	issuer, clientIds, paths, err := parse(c)
	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("Initiating OpenID Connect autentication middleware")
		return nil
	})

	configuration, err := openid.NewConfiguration(openid.ProvidersGetter(getProviderFunc(issuer, clientIds)),
		openid.ErrorHandler(onAuthenticateFailed))

	if err != nil {
		panic(err)
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &auth{
			Configuration: configuration,
			Paths:         paths,
			Next:          next,
		}
	})
	fmt.Println("OpenID Connect autentication middleware successfully initiated")

	return nil
}

func parseSingleValue(c *caddy.Controller) (string, error) {
	if !c.NextArg() {
		// we are expecting a value
		return "", c.ArgErr()
	}
	r := c.Val()
	if c.NextArg() {
		// we are expecting only one value.
		return "", c.ArgErr()
	}
	return r, nil
}

func parse(c *caddy.Controller) (issuer string, clientIds, paths []string, err error) {
	// This parses the following config blocks
	/*
	   openid_auth {
	       issuer http://issuer.com
	       clientid client.id.1
	       clientid client.id.2
	       path /service1/
	       path /service2/
	   }
	*/

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			// no argument passed, check the config block
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					path, err := parseSingleValue(c)
					if err != nil {
						return "", nil, nil, err
					}
					paths = append(paths, path)

				case "issuer":
					if issuer != "" {
						return issuer, clientIds, paths, errors.New("openidauth: only 1 issuer can be configured")
					}
					is, err := parseSingleValue(c)
					if err != nil {
						return "", nil, nil, err
					}
					issuer = is
				case "clientid":
					clientID, err := parseSingleValue(c)
					if err != nil {
						return "", nil, nil, err
					}
					clientIds = append(clientIds, clientID)
				}
			}
		default:
			// we don't want any arguments
			return "", nil, nil, c.ArgErr()
		}
	}
	if issuer == "" {
		return issuer, clientIds, paths, errors.New("Openidauth: issuer cannot be empty")
	}

	if len(clientIds) == 0 {
		return issuer, clientIds, paths, errors.New("Openidauth: at least 1 clientid needs to be set up")
	}

	if len(paths) == 0 {
		return issuer, clientIds, paths, errors.New("Openidauth: at least 1 path needs to be set up")
	}

	return issuer, clientIds, paths, nil
}
