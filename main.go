package main

import (
	"examples/GO-JWT-Authentication/controllers"
	"examples/GO-JWT-Authentication/initializers"
	"examples/GO-JWT-Authentication/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}
func main() {
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.LoginIn)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.Run() // listen and serve on 0.0.0.0:8080
}
