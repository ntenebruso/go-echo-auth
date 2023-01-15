package controllers

import (
	"app/models"
	"app/utils"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

type AuthController struct {}

func (AuthController) Login(c echo.Context) error {
	var user models.User;

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "field missing"})
	}

	if (strings.TrimSpace(user.Email) == "" || strings.TrimSpace(user.Password) == "") {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "blank email or password"})
	}

	var foundUser models.User;

	if err := utils.DB.Where("email = ? AND password = ?", user.Email, user.Password).First(&foundUser).Error; err != nil {
		return c.JSON(http.StatusUnauthorized, echo.Map{"message": "incorrect email or password"})
	}

	claims := &models.JWTUserClaim{
		ID: foundUser.ID,
		Email: foundUser.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte("secret"))

	if err != nil {
		return err
	}

	cookie := new(http.Cookie)
	cookie.Name = "user"
	cookie.Value = t
	cookie.Expires = time.Now().Add(time.Hour * 72)
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully signed in"})
}

func (AuthController) Signup(c echo.Context) error {
	var user models.User;

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "field missing"})
	}

	if (strings.TrimSpace(user.Email) == "" || strings.TrimSpace(user.Password) == "") {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "blank email or password"})
	}

	result := utils.DB.Create(&user)

	if result.Error != nil {
		return c.JSON(http.StatusForbidden, echo.Map{"message": result.Error.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully created user"})
}

func (AuthController) Logout(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "user"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(time.Hour * -1)
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully signed out"})
}

func (AuthController) User(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*models.JWTUserClaim)
	return c.JSON(http.StatusOK, echo.Map{"user": claims})
}