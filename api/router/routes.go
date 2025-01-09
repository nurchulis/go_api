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
		userRouter.GET("/:id/edit", controllers.EditUser)
		userRouter.PUT("/:id/update", controllers.UpdateUser)
		userRouter.DELETE("/:id/delete", controllers.DeleteUser)
		userRouter.GET("/all-trash", controllers.GetTrashedUsers)
		userRouter.DELETE("/delete-permanent/:id", controllers.PermanentlyDeleteUser)
	}

	// Task routes
	taskRouter := r.Group("/api/tasks")
	{
		taskRouter.GET("/", controllers.GetTask)
		taskRouter.POST("/create", controllers.CreateTask)
		taskRouter.GET("/:id/show", controllers.ShowTask)
		taskRouter.PUT("/:id/update", controllers.UpdateTask)
		taskRouter.DELETE("/:id/delete", controllers.DeleteTask)
		taskRouter.GET("/all-trash", controllers.GetTrashedTask)
		taskRouter.DELETE("/delete-permanent/:id", controllers.PermanentlyDeleteTask)
	}
}
