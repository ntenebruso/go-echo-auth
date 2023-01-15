package models

import (
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email string `json:"email" gorm:"unique"`
	Password string `json:"password"`
}

type JWTUserClaim struct {
	ID uint `json:"uid"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}