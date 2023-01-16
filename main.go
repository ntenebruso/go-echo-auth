package main

import (
	"app/controllers"
	"app/middleware"
	"app/utils"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

func main() {
	utils.InitDB()
	e := echo.New()

	e.Use(echomiddleware.Logger())
	e.Use(echomiddleware.Recover())

	authRouter := e.Group("/auth")
	authController := new(controllers.AuthController)

	authRouter.GET("/user", authController.User, middleware.JWTAuth)
	authRouter.GET("/logout", authController.Logout)
	authRouter.POST("/signup", authController.Signup)
	authRouter.POST("/login", authController.Login)

	e.Start("localhost:3000")
}