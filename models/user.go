package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"size:50;uniqueIndex"`
	Password string `gorm:"size:255;not null"`
	Token    string `gorm:"size:255"`
	ExpireAt time.Time
}
