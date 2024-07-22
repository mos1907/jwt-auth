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
			"message": "Usern Not Found",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "wrong password",
		})
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 1 gün geçerlilik süresi
	}

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	config := config.LoadConfig()
	accessTokenString, err := accessToken.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Create refresh token
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(), // 1 hafta geçerlilik süresi
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Store tokens in Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	rdb.Set(ctx, strconv.Itoa(int(user.ID)), accessTokenString, time.Hour*24)
	rdb.Set(ctx, "refresh_"+strconv.Itoa(int(user.ID)), refreshTokenString, time.Hour*24*7)

	return c.JSON(fiber.Map{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
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
	rdb.Del(ctx, "refresh_"+strconv.Itoa(int(user.ID)))

	return c.JSON(fiber.Map{
		"message": "Successful",
	})
}

func Refresh(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)

	// Generate new access token
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 1 gün geçerlilik süresi
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	config := config.LoadConfig()
	accessTokenString, err := accessToken.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Generate new refresh token
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(), // 1 hafta geçerlilik süresi
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Store new tokens in Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	rdb.Set(ctx, strconv.Itoa(int(user.ID)), accessTokenString, time.Hour*24)
	rdb.Set(ctx, "refresh_"+strconv.Itoa(int(user.ID)), refreshTokenString, time.Hour*24*7)

	return c.JSON(fiber.Map{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
	})
}
