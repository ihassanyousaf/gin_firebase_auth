package gin_firebase_auth

import (
	"context"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
)

var (
	tokenKey = "FIREBASE_ID_TOKEN"
)

type Config struct {
	AuthOverride     *map[string]interface{}
	DatabaseURL      string
	ProjectID        string
	ServiceAccountID string
	StorageBucket    string
}

type FirebaseAuth struct {
	auth *auth.Client
}

func New(cfg *Config) *FirebaseAuth {
	var app *firebase.App
	var err error
	client := &FirebaseAuth{}
	if cfg != nil {
		app, err = firebase.NewApp(context.Background(), &firebase.Config{
			AuthOverride:     cfg.AuthOverride,
			DatabaseURL:      cfg.DatabaseURL,
			ProjectID:        cfg.ProjectID,
			ServiceAccountID: cfg.ServiceAccountID,
			StorageBucket:    cfg.StorageBucket,
		})
	} else {
		app, err = firebase.NewApp(context.Background(), nil)
	}
	if err != nil {
		log.Fatal(err)
	}
	client.auth, err = app.Auth(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	return client
}

func (f *FirebaseAuth) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status":  http.StatusUnauthorized,
				"message": "Authorization header is missing",
			})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		idToken, err := f.auth.VerifyIDToken(context.Background(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status":  http.StatusUnauthorized,
				"message": err,
			})
			return
		}
		c.Set(tokenKey, idToken)
		c.Next()
	}
}

func ExtractClaims(c *gin.Context) *auth.Token {
	token, ok := c.Get(tokenKey)
	if !ok {
		return new(auth.Token)
	}
	return token.(*auth.Token)
}
