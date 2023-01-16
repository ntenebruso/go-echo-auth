package controllers

import (
	"app/models"
	"app/utils"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {}

func (AuthController) Login(c echo.Context) error {
	var data map[string]string

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "invalid JSON"})
	}

	if strings.TrimSpace(data["email"]) == "" || strings.TrimSpace(data["password"]) == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "blank email or password"})
	}

	var user models.User;

	result := utils.DB.Where("email = ?", data["email"]).First(&user)

	if result.Error != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "email not found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data["password"])); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "invalid password"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: strconv.Itoa(int(user.ID)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
	})

	t, err := token.SignedString([]byte("secret"))

	if err != nil {
		return err
	}

	cookie := new(http.Cookie)
	cookie.Name = "jwt"
	cookie.Path = "/"
	cookie.Value = t
	cookie.Expires = time.Now().Add(time.Hour * 72)
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully signed in"})
}

func (AuthController) Signup(c echo.Context) error {
	var data map[string]string

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "invalid JSON"})
	}

	if strings.TrimSpace(data["email"]) == "" || strings.TrimSpace(data["password"]) == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "blank email or password"})
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "error encrypting password"})
	}

	user := models.User{
		Email: data["email"],
		Password: string(hashedPwd),
	}

	result := utils.DB.Create(&user)

	if result.Error != nil {
		return c.JSON(http.StatusForbidden, echo.Map{"message": result.Error.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully created user"})
}

func (AuthController) Logout(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "jwt"
	cookie.Path = "/"
	cookie.Expires = time.Now().Add(time.Hour * -1)
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, echo.Map{"message": "successfully signed out"})
}

func (AuthController) User(c echo.Context) error {
	uid := c.Get("uid")

	var user models.User;

	utils.DB.Where("id = ?", uid).Select("id", "email").First(&user)

	return c.JSON(http.StatusOK, echo.Map{"user": user})
}