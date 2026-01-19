package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/api/idtoken"
)

// --- Global Variables ---
var (
	db                *sql.DB
	store             *sessions.CookieStore
	templates         *template.Template
	allowedBaseDomain string
	caddyAPIPort      string
	privateIPBlocks   []*net.IPNet
	subdomainRegex    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// --- Data Models ---
type Proxy struct {
	ID         string
	OwnerEmail string
	Domain     string
	Upstream   string
}

type ProxyGroup struct {
	Name  string
	Items []Proxy
}

type User struct {
	Email string
	Role  string
}

type PageData struct {
	Email         string
	Role          string
	ProxyGroups   []ProxyGroup
	Users         []User
	ClientId      string
	AllowedDomain string
	Error         string
}

// --- Initialization ---

func init() {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	}
	for _, cidr := range cidrs {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func initDB() {
	log.Println("Initializing SQLite database...")
	var err error
	db, err = sql.Open("sqlite3", "./caddy_data.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	queries := `
	CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, role TEXT);
	CREATE TABLE IF NOT EXISTS proxies (id TEXT PRIMARY KEY, owner_email TEXT, domain TEXT, upstream TEXT);
	`
	if _, err := db.Exec(queries); err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	admin := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	if admin != "" {
		db.Exec("INSERT OR IGNORE INTO users (email, role) VALUES (?, 'admin')", admin)
	}
}

// --- Validation Helpers ---

func validateSubdomain(sub string) error {
	if len(sub) > 100 {
		return fmt.Errorf("subdomain too long")
	}
	if !subdomainRegex.MatchString(sub) {
		return fmt.Errorf("invalid subdomain format")
	}
	if strings.Contains(sub, "..") {
		return fmt.Errorf("invalid subdomain: cannot contain consecutive dots")
	}
	return nil
}

func validateUpstream(upstream string) error {
	if strings.Contains(upstream, "://") {
		parts := strings.Split(upstream, "://")
		if len(parts) > 1 {
			upstream = parts[1]
		}
	}

	host := upstream
	if !strings.Contains(upstream, ":") {
	} else {
		h, _, err := net.SplitHostPort(upstream)
		if err == nil { host = h }
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("upstream must be a valid IP address")
	}

	isPrivate := false
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			isPrivate = true
			break
		}
	}
	if !isPrivate {
		return fmt.Errorf("security violation: upstream IP is not private")
	}
	return nil
}

// --- Sorting Helpers ---
func isDigit(b byte) bool { return '0' <= b && b <= '9' }

func naturalLess(s1, s2 string) bool {
	n1, n2 := len(s1), len(s2)
	i, j := 0, 0
	for i < n1 && j < n2 {
		if isDigit(s1[i]) && isDigit(s2[j]) {
			start1 := i
			for i < n1 && isDigit(s1[i]) { i++ }
			num1Str := s1[start1:i]
			start2 := j
			for j < n2 && isDigit(s2[j]) { j++ }
			num2Str := s2[start2:j]
			if len(num1Str) != len(num2Str) { return len(num1Str) < len(num2Str) }
			if num1Str != num2Str { return num1Str < num2Str }
			continue
		}
		if s1[i] != s2[j] { return s1[i] < s2[j] }
		i++; j++
	}
	return n1 < n2
}

// --- Caddy API Helpers ---

func updateCaddy(p Proxy) error {
	finalUpstream := p.Upstream
	if !strings.Contains(finalUpstream, ":") {
		finalUpstream = finalUpstream + ":80"
	}

	log.Printf("Caddy: Upserting route %s -> %s (ID: %s)", p.Domain, finalUpstream, p.ID)

	route := map[string]interface{}{
		"@id": p.ID,
		"match": []interface{}{
			map[string]interface{}{"host": []string{p.Domain}},
		},
		"handle": []interface{}{
			map[string]interface{}{
				"handler": "reverse_proxy",
				"upstreams": []interface{}{map[string]string{"dial": finalUpstream}},
			},
		},
	}
	jsonData, _ := json.Marshal(route)

	client := &http.Client{}

	idUrl := fmt.Sprintf("http://localhost:%s/id/%s", caddyAPIPort, p.ID)
	req, _ := http.NewRequest("PUT", idUrl, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return nil
	}

	createUrl := fmt.Sprintf("http://localhost:%s/config/apps/http/servers/srv0/routes", caddyAPIPort)
	resp2, err := client.Post(createUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil { return err }
	defer resp2.Body.Close()

	if resp2.StatusCode >= 400 {
		b, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("caddy error: %s", string(b))
	}
	return nil
}

func deleteCaddy(id string) {
	url := fmt.Sprintf("http://localhost:%s/id/%s", caddyAPIPort, id)
	req, _ := http.NewRequest("DELETE", url, nil)
	client := &http.Client{}
	client.Do(req)
}

// --- Sync Database to Caddy ---
func syncProxies() {
	log.Println("Sync: Starting synchronization of Database -> Caddy...")

	rows, err := db.Query("SELECT id, owner_email, domain, upstream FROM proxies")
	if err != nil {
		log.Printf("Sync Error: Failed to fetch proxies: %v", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var p Proxy
		rows.Scan(&p.ID, &p.OwnerEmail, &p.Domain, &p.Upstream)

		go func(proxy Proxy) {
			for i := 0; i < 5; i++ {
				if err := updateCaddy(proxy); err == nil {
					return
				}
				time.Sleep(2 * time.Second)
			}
			log.Printf("Sync Error: Could not push %s to Caddy after retries", proxy.Domain)
		}(p)
		count++
	}
	log.Printf("Sync: Queued %d proxies for update.", count)
}

// --- Middleware ---

func authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "caddy_session")
		if session.Values["email"] == nil {
			http.Redirect(w, r, "/CaddyCfg/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// --- Handlers ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", PageData{ClientId: os.Getenv("GOOGLE_CLIENT_ID")})
}

func handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { return }
	token := r.FormValue("credential")

	payload, err := idtoken.Validate(context.Background(), token, os.Getenv("GOOGLE_CLIENT_ID"))
	if err != nil {
		http.Error(w, "Invalid Token", 401)
		return
	}
	email := strings.ToLower(payload.Claims["email"].(string))

	var role string
	err = db.QueryRow("SELECT role FROM users WHERE email = ?", email).Scan(&role)
	if err == sql.ErrNoRows {
		templates.ExecuteTemplate(w, "login.html", PageData{Error: "Access Denied", ClientId: os.Getenv("GOOGLE_CLIENT_ID")})
		return
	}
	session, _ := store.Get(r, "caddy_session")
	session.Values["email"] = email
	session.Values["role"] = role
	session.Save(r, w)
	http.Redirect(w, r, "/CaddyCfg/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "caddy_session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/CaddyCfg/login", http.StatusFound)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "caddy_session")
	email := session.Values["email"].(string)
	role := session.Values["role"].(string)

	rows, _ := db.Query("SELECT id, owner_email, domain, upstream FROM proxies")

	groupsMap := make(map[string][]Proxy)

	for rows.Next() {
		var p Proxy
		rows.Scan(&p.ID, &p.OwnerEmail, &p.Domain, &p.Upstream)

		sub := strings.TrimSuffix(p.Domain, "." + allowedBaseDomain)
		parts := strings.Split(sub, ".")
		groupName := parts[len(parts)-1]
		if len(parts) == 1 && sub == allowedBaseDomain { groupName = "root" }

		groupsMap[groupName] = append(groupsMap[groupName], p)
	}
	rows.Close()

	var proxyGroups []ProxyGroup
	for name, items := range groupsMap {
		sort.Slice(items, func(i, j int) bool {
			return naturalLess(items[i].Domain, items[j].Domain)
		})
		proxyGroups = append(proxyGroups, ProxyGroup{Name: name, Items: items})
	}
	sort.Slice(proxyGroups, func(i, j int) bool {
		return naturalLess(proxyGroups[i].Name, proxyGroups[j].Name)
	})

	var users []User
	if role == "admin" {
		uRows, _ := db.Query("SELECT email, role FROM users")
		for uRows.Next() {
			var u User
			uRows.Scan(&u.Email, &u.Role)
			users = append(users, u)
		}
		uRows.Close()
	}

	templates.ExecuteTemplate(w, "index.html", PageData{
		Email: email, Role: role, ProxyGroups: proxyGroups, Users: users, AllowedDomain: allowedBaseDomain,
	})
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { return }
	session, _ := store.Get(r, "caddy_session")
	role := session.Values["role"].(string)
	email := session.Values["email"].(string)

	if role == "viewer" { http.Error(w, "Forbidden", 403); return }

	action := r.FormValue("action")

	if action == "delete" {
		id := r.FormValue("id")
		var owner string
		db.QueryRow("SELECT owner_email FROM proxies WHERE id=?", id).Scan(&owner)
		if role != "admin" && owner != email {
			http.Error(w, "Forbidden", 403)
			return
		}
		deleteCaddy(id)
		db.Exec("DELETE FROM proxies WHERE id=?", id)
	} else {
		subdomain := strings.ToLower(strings.TrimSpace(r.FormValue("subdomain")))
		upstream := strings.TrimSpace(r.FormValue("upstream"))

		if !strings.Contains(upstream, ":") {
			upstream = upstream + ":80"
		}

		if err := validateSubdomain(subdomain); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := validateUpstream(upstream); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		fullDomain := fmt.Sprintf("%s.%s", subdomain, allowedBaseDomain)
		newID := "proxy-" + subdomain
		p := Proxy{ID: newID, OwnerEmail: email, Domain: fullDomain, Upstream: upstream}

		if err := updateCaddy(p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		db.Exec("INSERT OR REPLACE INTO proxies (id, owner_email, domain, upstream) VALUES (?, ?, ?, ?)", newID, email, fullDomain, upstream)
	}
	http.Redirect(w, r, "/CaddyCfg/", http.StatusFound)
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { return }
	session, _ := store.Get(r, "caddy_session")
	if session.Values["role"] != "admin" { http.Error(w, "Forbidden", 403); return }

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	db.Exec("INSERT OR REPLACE INTO users (email, role) VALUES (?, ?)", email, r.FormValue("role"))
	http.Redirect(w, r, "/CaddyCfg/", http.StatusFound)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	godotenv.Load()

	allowedBaseDomain = os.Getenv("ALLOWED_DOMAIN")
	if allowedBaseDomain == "" { allowedBaseDomain = "co-test-site.com" }
	allowedBaseDomain = strings.TrimPrefix(allowedBaseDomain, ".")

	caddyAPIPort = os.Getenv("CADDY_API_PORT")
	if caddyAPIPort == "" { caddyAPIPort = "2019" }

	initDB()
	go syncProxies()

	templates = template.Must(template.ParseGlob("templates/*.html"))

	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{Path: "/", MaxAge: 86400 * 7, HttpOnly: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/auth/google", handleGoogleAuth)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/", authRequired(handleDashboard))
	mux.HandleFunc("/proxy", authRequired(handleProxy))
	mux.HandleFunc("/user", authRequired(handleUser))

	port := os.Getenv("PORT")
	if port == "" { port = "8080" }

	rootHandler := http.StripPrefix("/CaddyCfg", mux)

	log.Printf("Listening on :%s (Mapped to /CaddyCfg)...", port)
	if err := http.ListenAndServe(":"+port, rootHandler); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
