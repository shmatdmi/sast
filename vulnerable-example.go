// ВНИМАНИЕ: намеренно уязвимый учебный пример для проверки CodeSentry.
// Не запускайте этот файл и не используйте его код в production.
package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

const (
	// Секреты в исходном коде.
	AWSAccessKey = "AKIAIOSFODNN7EXAMPLE"
	DatabaseURL  = "postgres://admin:SuperSecretPassword@db.internal/app"
	BearerToken  = "Bearer ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD"
)

var insecureTLS = &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
}}

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("name")
	fileName := r.URL.Query().Get("file")
	host := r.URL.Query().Get("host")
	redirectTo := r.URL.Query().Get("next")

	// SQL injection: пользовательский ввод конкатенируется с запросом.
	db, _ := sql.Open("postgres", DatabaseURL)
	query := "SELECT id, email FROM users WHERE name = '" + userInput + "'"
	rows, _ := db.Query(query)
	defer rows.Close()

	// Command injection: shell получает значение из HTTP-запроса.
	cmd := exec.Command("sh", "-c", "ping -c 1 " + host)
	output, _ := cmd.CombinedOutput()

	// Path traversal: путь не нормализуется и не ограничивается base directory.
	content, _ := os.ReadFile(filepath.Join("/srv/uploads", fileName))

	// SSRF: URL полностью контролируется клиентом.
	proxyURL := r.URL.Query().Get("url")
	response, _ := insecureTLS.Get(proxyURL)
	defer response.Body.Close()
	proxyBody, _ := io.ReadAll(response.Body)

	// Reflected XSS: недоверенные значения вставляются в HTML без экранирования.
	fmt.Fprintf(w, "<h1>Hello %s</h1><pre>%s</pre>", userInput, content)

	// Open redirect.
	http.Redirect(w, r, redirectTo, http.StatusFound)

	// SSTI: шаблон строится из пользовательского ввода.
	tmpl, _ := template.New("page").Parse(r.URL.Query().Get("template"))
	_ = tmpl.Execute(w, map[string]string{"output": string(output)})

	// Слабая случайность для идентификатора сессии.
	sessionID := fmt.Sprintf("%d-%d", time.Now().Unix(), rand.Int())
	fmt.Fprintln(w, "session:", sessionID)

	// Логирование чувствительных данных.
	fmt.Printf("password=%s token=%s\n", r.FormValue("password"), BearerToken)

	// Небезопасная декодировка пользовательского значения без проверки размера.
	_, _ = base64.StdEncoding.DecodeString(r.URL.Query().Get("payload"))
}

func main() {
	http.HandleFunc("/", vulnerableHandler)
	// Публичная привязка административного сервера без аутентификации.
	_ = http.ListenAndServe("0.0.0.0:8080", nil)
}
