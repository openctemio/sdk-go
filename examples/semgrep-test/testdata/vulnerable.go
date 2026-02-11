// Sample vulnerable code for testing semgrep scanner
package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// SQL Injection vulnerability
func GetUser(db *sql.DB, userID string) (*User, error) {
	// BAD: SQL injection - user input directly in query
	query := "SELECT * FROM users WHERE id = '" + userID + "'"
	row := db.QueryRow(query)

	var user User
	err := row.Scan(&user.ID, &user.Name, &user.Email)
	return &user, err
}

// Command Injection vulnerability
func RunCommand(input string) ([]byte, error) {
	// BAD: Command injection - user input directly in command
	cmd := exec.Command("sh", "-c", "echo "+input)
	return cmd.Output()
}

// Path Traversal vulnerability
func ReadFile(w http.ResponseWriter, r *http.Request) {
	// BAD: Path traversal - user input directly in file path
	filename := r.URL.Query().Get("file")
	http.ServeFile(w, r, "/data/"+filename)
}

// Hardcoded credentials
func ConnectDB() (*sql.DB, error) {
	// BAD: Hardcoded password
	return sql.Open("mysql", "root:password123@tcp(localhost:3306)/mydb")
}

// Insecure random
func GenerateToken() string {
	// BAD: Using math/rand instead of crypto/rand
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[i%len(letters)] // Predictable
	}
	return string(b)
}

// Missing error check
func ProcessData(data []byte) {
	// BAD: Ignoring error
	result, _ := parseData(data)
	fmt.Println(result)
}

type User struct {
	ID    int
	Name  string
	Email string
}

func parseData(data []byte) (string, error) {
	return string(data), nil
}
