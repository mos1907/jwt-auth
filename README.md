
# JWT-Based Authentication System with Golang

In this article, we will create a JWT-based authentication system using Golang. Our system will use the following technologies:

- **Fiber**: A fast web framework
- **GORM**: ORM for interacting with PostgreSQL
- **JWT**: JSON Web Token for authentication
- **Redis**: Cache for token management
- **PostgreSQL**: Database for storing user data
- **Bcrypt**: Secure algorithm for password hashing

These are the components we will use within the Golang project. Additionally, for external project components:

- **Redis**: Cache for token management
- **PostgreSQL**: Database for storing user data

## Requirements

You will need the following tools to complete this project:

1. **Go**: Download the latest version from https://golang.org/dl/.

2. **PostgreSQL**: 
   - Download: https://www.postgresql.org/download/
   - IDE suggestion: pgAdmin (comes with PostgreSQL) or DBeaver (https://dbeaver.io/)
   
   After installing PostgreSQL:
   - Create a new database (e.g., `auth_system`)
   - Note down the username, password, and database name (we will use these in the `.env` file)

3. **Redis**: 
   - Download: https://redis.io/download
   - IDE suggestion: RedisInsight (https://redislabs.com/redis-enterprise/redis-insight/)
   
   After installing Redis:
   - It will run on `localhost:6379` by default
   - You can use RedisInsight to visualize the data

4. **IDE**: 
   - GoLand (https://www.jetbrains.com/go/) or 
   - Visual Studio Code (https://code.visualstudio.com/) with the Go extension

5. **Postman**: To test your API (https://www.postman.com/)

## Creating the Project

- First, create a new directory for the project and initialize the Go module:

- Install the necessary dependencies:

## Project Structure

Our project structure will be as follows:
<pre>
jwt-auth/
│
├── config/
│   └── config.go
├── database/
│   └── database.go
├── handlers/
│   └── auth.go
├── middleware/
│   └── auth.go
├── models/
│   └── user.go
├── .env
└── main.go
</pre>

### .env File

- Create a '.env' file and fill it with the following content using your database information:
``` ENV

DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
DB_PORT=5432
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
JWT_SECRET=your_jwt_secret
```

### Configuration

- Create 'config.go' file under the 'config' directory:
``` GO
package config

import (
    "log"
    "os"
    "github.com/joho/godotenv"
)

type Config struct {
    DBHost        string
    DBUser        string
    DBPassword    string
    DBName        string
    DBPort        string
    RedisAddr     string
    RedisPassword string
    RedisDB       int
    JWTSecret     string
}

func LoadConfig() Config {
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }

    return Config{
        DBHost:     os.Getenv("DB_HOST"),
        DBUser:     os.Getenv("DB_USER"),
        DBPassword: os.Getenv("DB_PASSWORD"),
        DBName:     os.Getenv("DB_NAME"),
        DBPort:     os.Getenv("DB_PORT"),
        RedisAddr:  os.Getenv("REDIS_ADDR"),
        RedisPassword: os.Getenv("REDIS_PASSWORD"),
        RedisDB:    os.Getenv("REDIS_DB"),
        JWTSecret:  os.Getenv("JWT_SECRET"),
    }
}
```

### Database Connection

- Create 'database.go' file under the 'database' directory:
``` GO
package database

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"jwt-auth/config"
	"log"
)

var DB *gorm.DB

func Connect(cfg config.Config) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Could not connect to database!", err)
	}
}

```

### Models

- Create 'user.go' file under the 'models' directory:
``` GO
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

```

### Handlers

- Create 'auth.go' file under the 'handlers' directory:
``` GO
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

```

### Middleware

- Create 'auth.go' file under the 'middleware' directory:
``` GO
package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"jwt-auth/config"
	"jwt-auth/database"
	"jwt-auth/models"
	"strings"
)

func Auth(c *fiber.Ctx) error {
	config := config.LoadConfig()
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "No authorization header"})
	}

// Extract the token by removing the "Bearer" part
	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return []byte(config.JWTSecret), nil
	})

	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userID, ok := claims["user_id"].(float64)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid token claims"})
		}

		var user models.User
		database.DB.First(&user, uint(userID))

		if user.ID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "User not found"})
		}

		c.Locals("user", user)
		return c.Next()
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid token"})
	}
}


```

### Main File

- Finally, create the 'main.go' file:

``` GO
package main

import (
	"github.com/gofiber/fiber/v2"
	"jwt-auth/config"
	"jwt-auth/database"
	"jwt-auth/handlers"
	"jwt-auth/middleware"
	"jwt-auth/models"
)

func main() {
	cfg := config.LoadConfig()

	app := fiber.New()

	database.Connect(cfg)
	models.Migrate(database.DB)

	app.Post("/register", handlers.Register)
	app.Post("/login", handlers.Login)

	app.Use(middleware.Auth)
	app.Get("/user", handlers.User)
	app.Post("/logout", handlers.Logout)
	app.Post("/refresh", handlers.Refresh)

	app.Listen(":6000")
}

```

## Running the Application

- Ensure that the PostgreSQL and Redis databases are running.
- After setting up your environment, you can run your application with the following command:
``` SH
go run main.go
```

