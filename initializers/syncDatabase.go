package initializers

import "examples/GO-JWT-Authentication/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
