---
title: "JWT-Based Authentication System with Golang"
date: 2024-07-22
lastmod: 2024-07-22
draft: false
tags: ["Golang", "JWT", "Redis", "PostgreSQL", "GORM", "Bcrypt", "Fiber", "authentication"]
authors: ["Murat"]
categories: ["Software Development"]
description: "JWT-Based Authentication System with Golang"
lightgallery: true
featuredImage: "gojwt.png"
---
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
<br>
<div align="center">
  <img src="/jwtwithgo/gorun.png" alt="Running the application">
  <br>
  *Figure 1: Running the Application*
</div>
- Your application should be running at http://localhost:6000, and you can test the endpoints using tools like Postman or cURL.

## Testing the Application

- I tested our application using Postman. You can also use Postman to test your application.

### Creating a User

- We will send a post request with Postman. In the address field, we write http://localhost:6000/register and in the Body section, select raw and write the following JSON. You can use any username and password.
``` JSON
{
    "username": "superuser",
    "password": "su12345"
}

``` 
<br>
<div align="center">
  <img src="/jwtwithgo/register.png" alt="Postman User Creation">
  <br>
  *Figure 2: Postman User Creation*
</div>

- The response to the register post sent with Postman looks like this:
<br>
<div align="center">
  <img src="/jwtwithgo/register2.png" alt="Postman Kullanıcı oluşturma Dönüş mesajı">
  <br>
  *Şekil 3: Postman Register Post Return *
</div>

- The record created in the database looks like this:
<br>
<div align="center">
  <img src="/jwtwithgo/register3.png" alt="Record in Database">
  <br>
  *Figure 4: Record Created in the Database*
</div>

### User Login

- We will send a post request with Postman. In the address field, we write http://localhost:6000/login and in the Body section, select raw and write the created username and password.
<br>
<div align="center">
  <img src="/jwtwithgo/login.png" alt="Postman User Login">
  <br>
  *Figure 5: User Login with Postman*
</div>

- As shown in the figure, the login process was successfully completed, and two JWT tokens, an access_token and a refresh_token, were created. These tokens are stored in our Redis database, which you can see in the image below. Note down the access_token as we will need it in the next step.
<br>
<br>
<div align="center">
  <img src="/jwtwithgo/redis.png" alt="Tokens Stored in Redis">
  <br>
  *Figure 6: Tokens Stored in Redis*
</div>

### Getting User Details

- We will make a get request with Postman. In the address field, we write http://localhost:6000/user and in the Authentication section, select Auth Type as Bearer Token and write the noted access_token in the token field.
<br>
<br>
<div align="center">
  <img src="/jwtwithgo/user.png" alt="User Details">
  <br>
  *Figure 7: User Details*
</div>

### Refreshing the Token

- We will send a post request with Postman. In the address field, we write http://localhost:6000/refresh without making any other changes, and click the send button.
<br>
<div align="center">
  <img src="/jwtwithgo/refresh.png" alt="Refresh Token">
  <br>
  *Figure 8: Token Refresh*
</div>

### Logging Out

- We will send a post request with Postman. In the address field, we write http://localhost:6000/logout without making any other changes, and click the send button.
<br>
<div align="center">
  <img src="/jwtwithgo/logout.png" alt="Logout">
  <br>
  *Figure 9: Logging Out*
</div>

## Conclusion

- In this article, I tried to explain step by step how to create a JWT-based authentication system using Golang, Fiber, GORM, PostgreSQL, and Redis. You now have a basic framework that you can extend with additional features according to your needs.

- I hope this article is helpful while developing your projects. If you have any questions or points to add, I would be happy to help!
- In my next articles, I will also be writing and sharing the Frontend part of this project using Svelte.
