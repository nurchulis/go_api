package helpers

import (
	"log"
	"os"

	"github.com/rollbar/rollbar-go"
)

// InitializeRollbar configures Rollbar SDK for error reporting
func InitializeRollbar() {
	rollbar.SetToken(os.Getenv("ROLLBAR_KEY"))
	rollbar.SetEnvironment("production")                 // Set the environment, e.g., "production"
	rollbar.SetCodeVersion("v2")                         // Set version of your code (e.g., Git hash or version tag)
	rollbar.SetServerHost("web.1")                       // Optional: Set the server host where errors originated
	rollbar.SetServerRoot("github.com/heroku/myproject") // Optional: Set the root path for your project files
}

// LogAndReportError logs an error locally and reports it to Rollbar
func LogAndReportError(err error, message string) {
	log.Printf("Error: %s: %v", message, err)
	rollbar.Error(err, map[string]interface{}{"message": message})
}

// LogAndReportInfo logs an informational message to Rollbar
func LogAndReportInfo(message string) {
	rollbar.Info(message)
}

// LogAndReportPanic captures a panic and sends it to Rollbar
func LogAndReportPanic(err interface{}) {
	rollbar.Error(err, map[string]interface{}{"message": "Captured Panic"})
}
