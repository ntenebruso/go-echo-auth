package models

type User struct {
	ID uint `json:"uid,omitempty" gorm:"primarykey"`
	Email string `json:"email,omitempty" gorm:"unique"`
	Password string `json:"password,omitempty"`
}