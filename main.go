package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/nurchulis/go-api/api/router"
	"github.com/nurchulis/go-api/config"
	"github.com/nurchulis/go-api/db/initializers"
	"github.com/nurchulis/go-api/internal/helpers"
	"github.com/rollbar/rollbar-go"
)

func init() {
	config.LoadEnvVariables()
	initializers.ConnectDB()
	helpers.InitializeRollbar()

}

func main() {
	// Defer Rollbar close to ensure logs are flushed before application exit
	defer rollbar.Close()
	// Log a simple info message to Rollbar
	helpers.LogAndReportInfo("Application has started successfully")

	fmt.Println("Hello auth")
	r := gin.Default()
	router.GetRoute(r)

	r.Run()
}
