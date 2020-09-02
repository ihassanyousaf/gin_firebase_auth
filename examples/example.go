package main

import (
	"fmt"
	"gin_firebase_auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.New()
	a := gin_firebase_auth.New(nil)
	auth := r.Group("/auth")
	auth.Use(a.Auth())
	auth.GET("/", func(c *gin.Context) {
		claims := gin_firebase_auth.ExtractClaims(c)
		fmt.Println(claims)
		c.String(http.StatusOK, "success")
	})
	r.Run(":4001")
}
