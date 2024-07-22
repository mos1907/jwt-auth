package handlers

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"jwt-auth/config"
	"jwt-auth/database"
	"jwt-auth/models"
	"strconv"
	"time"
)

var ctx = context.Background()

func Register(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)

	user := models.User{
		Username: data["username"],
		Password: string(password),
	}

	database.DB.Create(&user)

	return c.JSON(user)
}

func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user models.User
	database.DB.Where("username = ?", data["username"]).First(&user)

	if user.ID == 0 {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "Kullanıcı bulunamadı",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Yanlış şifre",
		})
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	config := config.LoadConfig()
	t, err := token.SignedString([]byte(config.JWTSecret))

	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	rdb.Set(ctx, strconv.Itoa(int(user.ID)), t, time.Hour*24)

	return c.JSON(fiber.Map{
		"token": t,
	})
}

func User(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	return c.JSON(user)
}

func Logout(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	config := config.LoadConfig()
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	rdb.Del(ctx, strconv.Itoa(int(user.ID)))

	return c.JSON(fiber.Map{
		"message": "Başarılı",
	})
}

func Refresh(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	config := config.LoadConfig()
	t, err := token.SignedString([]byte(config.JWTSecret))

	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	rdb.Set(ctx, strconv.Itoa(int(user.ID)), t, time.Hour*24)

	return c.JSON(fiber.Map{
		"token": t,
	})
}
