package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"unique"`
	Password string
}

func Migrate(db *gorm.DB) {
	db.AutoMigrate(&User{})
}
