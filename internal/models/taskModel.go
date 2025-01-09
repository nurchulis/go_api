package models

import (
	"time"

	"gorm.io/gorm"
)

type Task struct {
	ID          string         `gorm:"type:uuid;primaryKey" json:"id"` // Use UUID for better uniqueness
	Title       string         `gorm:"not null" json:"title"`
	Description string         `gorm:"type:text" json:"description"`
	Status      string         `json:"status"`   // Default string type, no need for gorm:type
	DueDate     time.Time      `json:"due_date"` // Added DueDate field for task deadlines
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"` // For soft delete functionality
}
