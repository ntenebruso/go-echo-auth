package main

import (
	"app/controllers"
	"app/models"
	"app/utils"

	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	utils.InitDB()
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	authRouter := e.Group("/auth")
	authController := new(controllers.AuthController)

	authRouter.GET("/user", authController.User, echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte("secret"),
		TokenLookup: "cookie:user",
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(models.JWTUserClaim)
		},
	}))
	authRouter.GET("/logout", authController.Logout)
	authRouter.POST("/signup", authController.Signup)
	authRouter.POST("/login", authController.Login)

	e.Start("localhost:3000")
}