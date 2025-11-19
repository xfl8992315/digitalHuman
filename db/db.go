package db

import (
	"errors"
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"server/models"
)

var DB *gorm.DB

var ErrUserNotFound = errors.New("user not found")

func Init() {
	var err error
	DB, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database:", err)
	}

	if err := DB.AutoMigrate(&models.User{}); err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	var count int64
	if err := DB.Model(&models.User{}).Count(&count).Error; err != nil {
		log.Fatal("failed to count users:", err)
	}

	if count == 0 {
		DB.Create(&models.User{
			Username: "admin",
			Password: "123654789",
			Token:    "",
			ExpireAt: time.Now().AddDate(1, 0, 0),
		})
	}
}

func FindUserByCredentials(username, password string) (*models.User, error) {
	var user models.User
	if err := DB.Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func GetUserByID(id uint) (*models.User, error) {
	var user models.User
	if err := DB.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func CreateUser(username, password string, expireAt time.Time) (*models.User, error) {
	user := models.User{
		Username: username,
		Password: password,
		ExpireAt: expireAt,
		Token:    "",
	}
	if err := DB.Create(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func ListUsers() ([]models.User, error) {
	var users []models.User
	if err := DB.Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func DeleteUserByID(id uint) error {
	if err := DB.Delete(&models.User{}, id).Error; err != nil {
		return err
	}
	return nil
}

func UpdateUserPassword(id uint, newPassword string) error {
	if err := DB.Model(&models.User{}).Where("id = ?", id).Update("password", newPassword).Error; err != nil {
		return err
	}
	return nil
}

func UpdateUserExpireAt(id uint, expireAt time.Time) error {
	if err := DB.Model(&models.User{}).Where("id = ?", id).Update("expire_at", expireAt).Error; err != nil {
		return err
	}
	return nil
}

func UpdateUserToken(id uint, token string) error {
	if err := DB.Model(&models.User{}).Where("id = ?", id).Update("token", token).Error; err != nil {
		return err
	}
	return nil
}
