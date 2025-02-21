package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-ini/ini"
	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var (
    tokenURL     string
    gqlURL       string
    clientID     string
    clientSecret string
)

func loadAPIConfig() error {
    cfg, err := ini.Load("config.ini")
    if err != nil {
        return err
    }

    section := cfg.Section("api")
    tokenURL = section.Key("token_url").String()
    gqlURL = section.Key("gql_url").String()
    clientID = section.Key("client_id").String()
    clientSecret = section.Key("client_secret").String()

    return nil
}


func loadConfig() (string, error) {
	cfg, err := ini.Load("config.ini")
	if err != nil {
		return "", err
	}
	return cfg.Section("freepbx").Key("freepbxconfigpath").String(), nil
}

func parsePHPConfig(filePath string) (map[string]string, error) {
	content, err := os.ReadFile(filePath) // ioutil o'rniga os.ReadFile ishlatilmoqda
	if err != nil {
		return nil, err
	}

	config := make(map[string]string)
	re := regexp.MustCompile(`\$amp_conf\[\"(.*?)\"\] = \"(.*?)\";`)
	matches := re.FindAllStringSubmatch(string(content), -1)
	for _, match := range matches {
		config[match[1]] = match[2]
	}
	return config, nil
}

func connectDB(configPath string) error {
	phpConfig, err := parsePHPConfig(configPath)
	if err != nil {
		return err
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", phpConfig["AMPDBUSER"], phpConfig["AMPDBPASS"], phpConfig["AMPDBHOST"], phpConfig["AMPDBNAME"])
	_db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	db = _db
	return db.Ping()
}

func getExtensions(c *gin.Context) {
	idStr := c.Param("id") // ID parametrini olish
	if idStr != "" {       // Agar ID berilgan bo'lsa, faqat bitta extensionni qaytarish
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
			return
		}

		var secret string

		query := `
			SELECT 
				MAX(CASE WHEN keyword = 'secret' THEN data END) AS secret
			FROM sip
			WHERE id = ?;
		`

		err = db.QueryRow(query, id).Scan(&secret)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "Extension not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"extension_id": id,
			"secret":       secret,
		})
		return
	}

	// Agar ID berilmagan bo'lsa, barcha extensionlarni olish
	rows, err := db.Query(`
		SELECT id, 
			MAX(CASE WHEN keyword = 'secret' THEN data END) AS secret
		FROM sip
		GROUP BY id;
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var extensions []gin.H
	for rows.Next() {
		var id int
		var secret string
		if err := rows.Scan(&id, &secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		extensions = append(extensions, gin.H{
			"extension_id": id,
			"secret":       secret,
		})
	}

	c.JSON(http.StatusOK, gin.H{"extensions": extensions})
}

func getExtensionsByIDs(c *gin.Context, extensionIDs []int) {
	// Agar extension ro‘yxati bo‘sh bo‘lsa, hech narsa qaytarmaymiz
	if len(extensionIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"extensions": []map[string]interface{}{}})
		return
	}

	// SQL queryni dinamik shakllantirish
	query := "SELECT id, data FROM sip WHERE keyword='secret' AND id IN ("
	params := []interface{}{}
	for i, id := range extensionIDs {
		if i > 0 {
			query += ","
		}
		query += "?"
		params = append(params, id)
	}
	query += ");"

	// So‘rovni bajarish
	rows, err := db.Query(query, params...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	// Natijalarni yig‘ish
	var extensions []map[string]interface{}
	for rows.Next() {
		var id int
		var secret string
		if err := rows.Scan(&id, &secret); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		extensions = append(extensions, gin.H{"extension_id": id, "secret": secret})
	}

	c.JSON(http.StatusOK, gin.H{"extensions": extensions})
}

func getAccessToken() (string, error) {
	data := "grant_type=client_credentials&client_id=" + clientID + "&client_secret=" + clientSecret
	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if accessToken, ok := result["access_token"].(string); ok {
		return accessToken, nil
	}
	return "", fmt.Errorf("error getting token")
}

func createExtensionAPI(extension map[string]interface{}, token string) error {
	query := fmt.Sprintf(`mutation { addExtension(input: {name: "%s", email: "%s", extensionId: "%d", tech: "%s", maxContacts: "%d" }) { status message } }`,
		extension["name"], extension["email"], int(extension["extension_id"].(float64)), extension["technology"], int(extension["max_contacts"].(float64)))

	payload := map[string]string{"query": query}
	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", gqlURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("API javobini o'qishda xatolik")
	}

	if errors, exists := response["errors"]; exists {
		return fmt.Errorf("API xatosi: %v", errors)
	}

	return nil
}

func validateExtension(ext map[string]interface{}) error {
	requiredFields := []string{"extension_id", "name", "email", "technology", "max_contacts"}
	for _, field := range requiredFields {
		if _, exists := ext[field]; !exists {
			return fmt.Errorf("key not found: %s", field)
		}
	}

	if _, ok := ext["extension_id"].(float64); !ok {
		return fmt.Errorf("extension_id is of the wrong type, it should be float64")
	}
	if _, ok := ext["name"].(string); !ok {
		return fmt.Errorf("name is of the wrong type, it must be a string")
	}
	if _, ok := ext["email"].(string); !ok {
		return fmt.Errorf("email is of the wrong type, it must be a string")
	}
	if _, ok := ext["technology"].(string); !ok {
		return fmt.Errorf("technology is of the wrong type, it should be a string")
	}
	if _, ok := ext["max_contacts"].(float64); !ok {
		return fmt.Errorf("max_contacts is of the wrong type, it should be float64")
	}
	return nil
}

func editPasswords(passwordUpdates []map[string]interface{}) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare("UPDATE sip SET data = ? WHERE keyword = 'secret' AND id = ?")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, update := range passwordUpdates {
		_, err := stmt.Exec(update["password"], update["extension_id"])
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func createExtension(c *gin.Context) {
	var extensions []map[string]interface{}

	if err := c.BindJSON(&extensions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON format error"})
		return
	}

	var extensionIDs []int
	var passwordUpdates []map[string]interface{}

	for _, ext := range extensions {
		if err := validateExtension(ext); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		extensionID := int(ext["extension_id"].(float64))
		extensionIDs = append(extensionIDs, extensionID)

		if password, exists := ext["password"]; exists {
			if passStr, ok := password.(string); ok {
				passwordUpdates = append(passwordUpdates, map[string]interface{}{
					"extension_id": extensionID,
					"password":     passStr,
				})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("password is of the wrong type for extension_id %d", extensionID)})
				return
			}
		}
	}

	token, err := getAccessToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting token in FreePBX"})
		return
	}

	for _, ext := range extensions {
		if err := createExtensionAPI(ext, token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	if len(passwordUpdates) > 0 {
		if err := editPasswords(passwordUpdates); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating passwords: " + err.Error()})
			return
		}
	}

	cmd := exec.Command("fwconsole", "reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reloading FreePBX: " + err.Error()})
		return
	}

	getExtensionsByIDs(c, extensionIDs)
}

func updateExtension(c *gin.Context) {
	id := c.Param("id") // URL'dan extension ID olish

	var data struct {
		Password string `json:"password"`
	}

	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Password bo'sh yoki uzunligi 8 tadan kam bo'lsa, xatolik qaytaramiz
	if len(data.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database transaction error: " + err.Error()})
		return
	}

	stmt, err := tx.Prepare("UPDATE sip SET data = ? WHERE keyword = 'secret' AND id = ?")
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SQL prepare error: " + err.Error()})
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(data.Password, id)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password: " + err.Error()})
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction commit error: " + err.Error()})
		return
	}
	cmd := exec.Command("fwconsole", "reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reloading FreePBX: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":      "Extension updated successfully",
		"extension_id": id,
		"password":     data.Password,
	})
}

func deleteExtension(c *gin.Context) {
	id := c.Param("id")

	// Transaction boshlaymiz
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction: " + err.Error()})
		return
	}

	// O'chirish SQL so'rovlarini tayyorlash
	queries := []string{
		"DELETE FROM users WHERE extension = ?",
		"DELETE FROM devices WHERE id = ?",
		"DELETE FROM pjsip WHERE id = ?",
		"DELETE FROM sip WHERE id = ?",
	}

	for _, query := range queries {
		_, err := tx.Exec(query, id)
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete extension: " + err.Error()})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction commit failed: " + err.Error()})
		return
	}
	cmd := exec.Command("fwconsole", "reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reloading FreePBX: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Extension deleted successfully"})
}

func main() {
	configPath, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := loadAPIConfig(); err != nil {
        log.Fatalf("Failed to load API config: %v", err)
    }

	if err := connectDB(configPath); err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	r := gin.Default()
	r.GET("/extensions", getExtensions)
	r.GET("/extensions/:id", getExtensions)
	r.POST("/extensions", createExtension)
	r.PUT("/extensions/:id", updateExtension)
	r.DELETE("/extensions/:id", deleteExtension)

	log.Println("Server running on :8080")
	r.Run(":8080")
}
