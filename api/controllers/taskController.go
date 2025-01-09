package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/nurchulis/go-api/db/initializers"
	"github.com/nurchulis/go-api/internal/consts"
	format_errors "github.com/nurchulis/go-api/internal/format-errors"
	"github.com/nurchulis/go-api/internal/helpers"
	"github.com/nurchulis/go-api/internal/models"
	"github.com/nurchulis/go-api/internal/pagination"
	"github.com/nurchulis/go-api/internal/validations"
	"gorm.io/gorm"
)

// CreateTask creates a task
func CreateTask(c *gin.Context) {
	// Get task input from request
	var taskInput struct {
		Title       string `json:"title" binding:"required,min=2,max=200"`
		Description string `json:"description" binding:"required"`
		Status      string `json:"status" binding:"required"`
		DueDate     string `json:"due_date" binding:"required"`
	}

	if err := c.ShouldBindJSON(&taskInput); err != nil {
		if errs, ok := err.(validator.ValidationErrors); ok {
			helpers.LogAndReportError(errs, "validation input task") // Log validation error

			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"validations": validations.FormatValidationErrors(errs),
			})

			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Parse DueDate
	dueDate, err := time.Parse(time.RFC3339, taskInput.DueDate)
	if err != nil {
		helpers.LogAndReportError(err, "error parse duedate")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid dueDate format. Use ISO 8601 format (e.g., 2025-01-09T15:04:05Z).",
		})
		return
	}

	// Create a task
	task := models.Task{
		ID:          uuid.New().String(),
		Title:       taskInput.Title,
		Description: taskInput.Description,
		Status:      taskInput.Status,
		DueDate:     dueDate,
	}

	result := initializers.DB.Create(&task)

	if result.Error != nil {
		format_errors.InternalServerError(c)
		return
	}

	helpers.LogAndReportInfo("Successfully created task")

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"code":    consts.OK,
		"message": "Task created successfully",
		"task":    task,
	})
}

// GetTask gets all the tasks
func GetTask(c *gin.Context) {
	// Get all the tasks
	var tasks []models.Task

	// Parse query parameters
	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)

	perPageStr := c.DefaultQuery("perPage", "5")
	perPage, _ := strconv.Atoi(perPageStr)

	// Fetch tasks with pagination
	result, err := pagination.Paginate(initializers.DB, page, perPage, nil, &tasks)
	if err != nil {
		helpers.LogAndReportError(err, "error get paginate list")
		format_errors.InternalServerError(c)
		return
	}

	// Format tasks for response
	formattedTasks := []map[string]interface{}{}
	for _, task := range tasks {
		formattedTasks = append(formattedTasks, map[string]interface{}{
			"id":          task.ID,
			"title":       task.Title,
			"description": task.Description,
			"status":      task.Status,
			"due_date":    task.DueDate.Format("2006-01-02"), // Format date as YYYY-MM-DD
		})
	}

	// Extract pagination details from the result
	paginationDetails := map[string]interface{}{
		"current_page": result.CurrentPage,
		"total_pages":  result.LastPage,
		"total_tasks":  result.Total,
	}

	// Return the response
	c.JSON(http.StatusOK, gin.H{
		" code":      consts.OK,
		"tasks":      formattedTasks,
		"pagination": paginationDetails,
	})
}

// ShowTask finds a task by ID
func ShowTask(c *gin.Context) {
	// Get the id from the URL
	id := c.Param("id")
	cacheKey := "task_" + id

	var cachedTask map[string]interface{}
	err := helpers.GetFromCache(cacheKey, &cachedTask)
	if err == nil && cachedTask != nil {
		c.JSON(http.StatusOK, gin.H{
			"code":    200,
			"message": "Successfully show task",
			"task":    cachedTask,
		})
		return
	}

	// Find the task
	var task models.Task
	result := initializers.DB.Where("id = ?", id).First(&task)

	// Handle not found or other errors
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"code":  consts.NotFound,
				"error": "Task not found",
			})
		} else {
			format_errors.InternalServerError(c)
		}
		return
	}

	transformTask := map[string]interface{}{
		"id":          task.ID,
		"title":       task.Title,
		"description": task.Description,
		"status":      task.Status,
		"due_date":    task.DueDate.Format("2006-01-02"),
	}

	err = helpers.SetToCache(cacheKey, transformTask, time.Hour)
	if err != nil {
		helpers.LogAndReportError(err, "error setting cache")
	}

	// Return the task
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"message": "Successfully show task",
		"task":    transformTask,
	})
}

// UpdateTask updates a task by ID
func UpdateTask(c *gin.Context) {
	// Get the id from the URL
	id := c.Param("id")
	cacheKey := "task_" + id

	// Get the data from the request body
	var taskInput struct {
		Title       string `json:"title" binding:"required,min=2,max=200"`
		Description string `json:"description" binding:"required"`
		Status      string `json:"status" binding:"required"`
		DueDate     string `json:"due_date" binding:"required"` // ISO 8601 format
	}

	if err := c.ShouldBindJSON(&taskInput); err != nil {
		if errs, ok := err.(validator.ValidationErrors); ok {
			helpers.LogAndReportError(errs, "validation input task update") // Log validation error
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"validations": validations.FormatValidationErrors(errs),
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"code":  consts.BadResponse,
			"error": err.Error(),
		})
		return
	}

	// Find the task by id
	var task models.Task
	result := initializers.DB.Where("id = ?", id).First(&task)

	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"code":  consts.NotFound,
				"error": "Task not found",
			})
		} else {
			format_errors.InternalServerError(c)
		}
		return
	}

	// Parse DueDate
	dueDate, err := time.Parse(time.RFC3339, taskInput.DueDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid dueDate format. Use ISO 8601 format (e.g., 2025-01-09T15:04:05Z).",
		})
		return
	}

	err = helpers.DelCache(cacheKey)
	if err == nil {
		fmt.Println("Error delete cache")
		helpers.LogAndReportError(err, "error delete cache") // Log validation error
	}

	// Update the task
	task.Title = taskInput.Title
	task.Description = taskInput.Description
	task.Status = taskInput.Status
	task.DueDate = dueDate

	result = initializers.DB.Save(&task)

	if result.Error != nil {
		format_errors.InternalServerError(c)
		return
	}

	transformTask := map[string]interface{}{
		"id":          task.ID,
		"title":       task.Title,
		"description": task.Description,
		"status":      task.Status,
		"due_date":    task.DueDate.Format("2006-01-02"),
	}

	err = helpers.SetToCache(cacheKey, transformTask, time.Hour)
	if err != nil {
		helpers.LogAndReportError(err, "error setting cache")
	}

	// Return the updated task
	c.JSON(http.StatusOK, gin.H{
		"code":    consts.OK,
		"message": "Task updated successfully",
		"task":    transformTask,
	})
}

// DeleteTask deletes a task by ID
func DeleteTask(c *gin.Context) {
	// Get the id from the url
	id := c.Param("id")
	var task models.Task

	result := initializers.DB.Where("id = ?", id).First(&task)
	if err := result.Error; err != nil {
		format_errors.RecordNotFound(c, err)
		return
	}

	// Delete the task
	initializers.DB.Delete(&task)

	// Return response
	c.JSON(http.StatusOK, gin.H{
		"message": "The task has been deleted successfully",
	})
}

// GetTr ashedTask retrieves all tasks that have been marked as deleted
func GetTrashedTask(c *gin.Context) {
	// Get the task
	var task []models.Task

	pageStr := c.DefaultQuery("page", "1")
	page, _ := strconv.Atoi(pageStr)

	perPageStr := c.DefaultQuery("perPage", "5")
	perPage, _ := strconv.Atoi(perPageStr)

	result, err := pagination.Paginate(initializers.DB.Unscoped().Where("deleted_at IS NOT NULL"), page, perPage, nil, &task)
	if err != nil {
		format_errors.InternalServerError(c)
		return
	}

	// Return the tasks
	c.JSON(http.StatusOK, gin.H{
		"result": result,
	})
}

// PermanentlyDeleteTask permanently deletes a task by ID
func PermanentlyDeleteTask(c *gin.Context) {
	// Get id from url
	id := c.Param("id")
	var task models.Task

	// Find the task
	if err := initializers.DB.Unscoped().First(&task, id).Error; err != nil {
		format_errors.RecordNotFound(c, err)
		return
	}

	// Delete the task
	initializers.DB.Unscoped().Delete(&task)

	// Return response
	c.JSON(http.StatusOK, gin.H{
		"message": "The task has been deleted permanently",
	})
}
