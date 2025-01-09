package tests

import (
	"log"

	"github.com/joho/godotenv"
	"github.com/nurchulis/go-api/db/initializers"
	"github.com/nurchulis/go-api/internal/models"
)

// DatabaseRefresh runs fresh migration
func DatabaseRefresh() {
	// Load env
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect DB
	initializers.ConnectDB()

	// Drop all the tables
	err = initializers.DB.Migrator().DropTable(models.User{})
	if err != nil {
		log.Fatal("Table dropping failed")
	}

	// Migrate again
	err = initializers.DB.AutoMigrate(models.User{})

	if err != nil {
		log.Fatal("Migration failed")
	}
}
