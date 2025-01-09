package main

import (
	"log"

	"github.com/nurchulis/go-api/config"
	"github.com/nurchulis/go-api/db/initializers"
	"github.com/nurchulis/go-api/internal/models"
)

func init() {
	config.LoadEnvVariables()
	initializers.ConnectDB()
}

func main() {
	err := initializers.DB.Migrator().DropTable(models.User{}, models.Task{})
	if err != nil {
		log.Fatal("Table dropping failed")
	}

	err = initializers.DB.AutoMigrate(models.User{}, models.Task{})

	if err != nil {
		log.Fatal("Migration failed")
	}
}
