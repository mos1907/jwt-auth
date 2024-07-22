package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"jwt-auth/config"
	"jwt-auth/database"
	"jwt-auth/models"
)

func Auth(c *fiber.Ctx) error {
	config := config.LoadConfig()
	tokenString := c.Get("Authorization")

	if tokenString == "" {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte(config.JWTSecret), nil
	})

	if err != nil {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		var user models.User
		database.DB.First(&user, claims["user_id"])

		if user.ID == 0 {
			return c.SendStatus(fiber.StatusUnauthorized)
		}

		c.Locals("user", user)
		return c.Next()
	} else {
		return c.SendStatus(fiber.StatusUnauthorized)
	}
}
