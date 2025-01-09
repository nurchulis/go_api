package helpers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nurchulis/go-api/api/middleware"
)

// GetAuthUser returns the authenticated user details from the Gin context
func GetAuthUser(c *gin.Context) *middleware.AuthUser {
	authUser, exists := c.Get("authUser")

	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get the user",
		})
		return nil
	}

	if user, ok := authUser.(middleware.AuthUser); ok {
		return &user
	}

	return nil
}
