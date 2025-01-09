package router

import (
	"github.com/gin-gonic/gin"
	"github.com/nurchulis/go-api/api/controllers"
	"github.com/nurchulis/go-api/api/middleware"
)

func GetRoute(r *gin.Engine) {
	// User routes
	r.POST("/api/signup", controllers.Signup)
	r.POST("/api/login", controllers.Login)

	r.Use(middleware.RequireAuth)
	r.POST("/api/logout", controllers.Logout)
	userRouter := r.Group("/api/users")
	{
		userRouter.GET("/", controllers.GetUsers)
	}

	// Task routes
	taskRouter := r.Group("/api/tasks")
	{
		taskRouter.GET("/", controllers.GetTask)
		taskRouter.POST("/", controllers.CreateTask)
		taskRouter.GET("/:id", controllers.ShowTask)
		taskRouter.PUT("/:id", controllers.UpdateTask)
		taskRouter.DELETE("/:id", controllers.DeleteTask)
		taskRouter.GET("/all-trash", controllers.GetTrashedTask)
		taskRouter.DELETE("/delete-permanent/:id", controllers.PermanentlyDeleteTask)
	}
}
