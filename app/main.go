package main

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
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
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
	"google.golang.org/api/idtoken"
)

//go:embed templates/*
var templateFS embed.FS

// --- Global Variables ---
var (
	db                *sql.DB
	store             *sessions.CookieStore
	templates         *template.Template
	allowedBaseDomain string
	caddyAPIPort      string
	version           = "1.31"
	privateIPBlocks   []*net.IPNet
	subdomainRegex    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	caddyConfigMu     sync.Mutex
)

// --- Data Models ---
type Proxy struct {
	ID           string
	OwnerEmail   string
	Domain       string
	Upstream     string
	UpstreamTLS  bool
	TLSInsecure  bool
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
	Version       string
	Error         string
	SyncStatus    string
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
	db, err = sql.Open("sqlite", "./caddy_data.db")
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

	migrations := []string{
		`ALTER TABLE proxies ADD COLUMN upstream_tls INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE proxies ADD COLUMN tls_insecure INTEGER NOT NULL DEFAULT 0`,
	}
	for _, q := range migrations {
		if _, err := db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			log.Printf("DB migration note: %v", err)
		}
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

func finalizeUpstream(upstream string, tls bool) string {
	if strings.Contains(upstream, ":") {
		return upstream
	}
	if tls {
		return upstream + ":443"
	}
	return upstream + ":80"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
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

// reverseProxyHandle returns a Caddy reverse_proxy handler tuned for long-lived
// streaming responses (SSE, WebSockets). Without flush_interval and disabled
// upstream compression, events can be buffered or gzip-encoded and never reach clients.
func reverseProxyHandle(finalUpstream string, upstreamTLS, tlsInsecure bool) map[string]interface{} {
	transport := map[string]interface{}{
		"protocol":    "http",
		"compression": false,
	}
	if upstreamTLS {
		tls := map[string]interface{}{}
		if tlsInsecure {
			tls["insecure_skip_verify"] = true
		}
		transport["tls"] = tls
	}

	return map[string]interface{}{
		"handler":        "reverse_proxy",
		"upstreams":      []interface{}{map[string]string{"dial": finalUpstream}},
		"flush_interval": -1,
		"transport":      transport,
	}
}

func caddyRoutesURL() string {
	return fmt.Sprintf("http://localhost:%s/config/apps/http/servers/srv0/routes", caddyAPIPort)
}

func fetchCaddyRoutes() ([]map[string]interface{}, error) {
	resp, err := http.Get(caddyRoutesURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch routes (%d): %s", resp.StatusCode, string(b))
	}
	var routes []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return nil, err
	}
	return routes, nil
}

func postCaddyRoute(p Proxy) error {
	finalUpstream := finalizeUpstream(p.Upstream, p.UpstreamTLS)
	route := buildCaddyRoute(p, finalUpstream)
	jsonData, _ := json.Marshal(route)

	resp, err := http.Post(caddyRoutesURL(), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("caddy POST route %s error (%d): %s", p.ID, resp.StatusCode, string(b))
}

func deleteCaddyRouteID(proxyID string) {
	url := fmt.Sprintf("http://localhost:%s/id/%s", caddyAPIPort, proxyID)
	req, _ := http.NewRequest("DELETE", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func hostMatcherIncludesDomain(hostVal interface{}, domain string) bool {
	switch hosts := hostVal.(type) {
	case string:
		return hosts == domain
	case []interface{}:
		for _, h := range hosts {
			if hs, ok := h.(string); ok && hs == domain {
				return true
			}
		}
	case []string:
		for _, hs := range hosts {
			if hs == domain {
				return true
			}
		}
	}
	return false
}

func routeMatchers(route map[string]interface{}) []map[string]interface{} {
	m, ok := route["match"]
	if !ok {
		return nil
	}
	switch v := m.(type) {
	case []interface{}:
		entries := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if mobj, ok := item.(map[string]interface{}); ok {
				entries = append(entries, mobj)
			}
		}
		return entries
	case map[string]interface{}:
		return []map[string]interface{}{v}
	}
	return nil
}

// routeMatchesProxy reports whether a Caddy route belongs to the given proxy.
func routeMatchesProxy(route map[string]interface{}, proxyID, domain string) bool {
	if proxyID != "" {
		if id, ok := route["@id"].(string); ok && id == proxyID {
			return true
		}
	}
	if domain == "" {
		return false
	}
	for _, mobj := range routeMatchers(route) {
		if hostMatcherIncludesDomain(mobj["host"], domain) {
			return true
		}
	}
	return false
}

// routeIsManagedByControlPlane reports routes owned by caddy-control and safe to replace.
func routeIsManagedByControlPlane(route map[string]interface{}, proxies []Proxy) bool {
	if id, ok := route["@id"].(string); ok && strings.HasPrefix(id, "proxy-") {
		return true
	}
	for _, p := range proxies {
		if routeMatchesProxy(route, p.ID, p.Domain) {
			return true
		}
	}
	return false
}

// removeManagedRoutesFromArray deletes caddy-control routes from srv0/routes by index.
// Caddy's admin API cannot replace the whole routes array with PUT (409 conflict); use DELETE per index.
func removeManagedRoutesFromArray(proxies []Proxy) (int, error) {
	routes, err := fetchCaddyRoutes()
	if err != nil {
		return 0, err
	}

	var indices []int
	for i, route := range routes {
		if routeIsManagedByControlPlane(route, proxies) {
			indices = append(indices, i)
		}
	}

	removed := 0
	for i := len(indices) - 1; i >= 0; i-- {
		url := fmt.Sprintf("%s/%d", caddyRoutesURL(), indices[i])
		req, _ := http.NewRequest("DELETE", url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return removed, err
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return removed, fmt.Errorf("delete route index %d (%d)", indices[i], resp.StatusCode)
		}
		removed++
	}
	return removed, nil
}

func writeProxiesToCaddy(proxies []Proxy) error {
	caddyConfigMu.Lock()
	defer caddyConfigMu.Unlock()

	// Clear ID index entries and orphaned array routes before re-adding.
	routes, err := fetchCaddyRoutes()
	if err != nil {
		return err
	}
	seenIDs := make(map[string]bool)
	for _, route := range routes {
		if id, ok := route["@id"].(string); ok && strings.HasPrefix(id, "proxy-") {
			seenIDs[id] = true
		}
	}
	for _, p := range proxies {
		seenIDs[p.ID] = true
	}
	for id := range seenIDs {
		deleteCaddyRouteID(id)
	}

	removed, err := removeManagedRoutesFromArray(proxies)
	if err != nil {
		return err
	}
	if removed > 0 {
		log.Printf("Caddy: Removed %d stale route(s) from routes array", removed)
	}

	for _, p := range proxies {
		if err := postCaddyRoute(p); err != nil {
			return err
		}
	}
	log.Printf("Caddy: Wrote %d proxy route(s) to routes array", len(proxies))
	return nil
}

func loadAllProxies() ([]Proxy, error) {
	rows, err := db.Query("SELECT id, owner_email, domain, upstream, upstream_tls, tls_insecure FROM proxies")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proxies []Proxy
	for rows.Next() {
		var p Proxy
		var upstreamTLS, tlsInsecure int
		rows.Scan(&p.ID, &p.OwnerEmail, &p.Domain, &p.Upstream, &upstreamTLS, &tlsInsecure)
		p.UpstreamTLS = upstreamTLS != 0
		p.TLSInsecure = tlsInsecure != 0
		proxies = append(proxies, p)
	}
	return proxies, nil
}

func buildCaddyRoute(p Proxy, finalUpstream string) map[string]interface{} {
	return map[string]interface{}{
		"@id": p.ID,
		"match": []interface{}{
			map[string]interface{}{"host": []string{p.Domain}},
		},
		"handle": []interface{}{
			reverseProxyHandle(finalUpstream, p.UpstreamTLS, p.TLSInsecure),
		},
	}
}

// --- Sync Database to Caddy ---

func syncProxiesToCaddy() error {
	proxies, err := loadAllProxies()
	if err != nil {
		return err
	}
	var writeErr error
	for i := 0; i < 5; i++ {
		if writeErr = writeProxiesToCaddy(proxies); writeErr == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return writeErr
}

func syncProxies() {
	log.Println("Sync: Starting synchronization of Database -> Caddy...")
	if err := syncProxiesToCaddy(); err != nil {
		log.Printf("Sync Error: %v", err)
		return
	}
	proxies, _ := loadAllProxies()
	log.Printf("Sync: Wrote %d proxy route(s) to Caddy.", len(proxies))
}

func triggerCaddySync() {
	go func() {
		if err := syncProxiesToCaddy(); err != nil {
			log.Printf("Sync Error: background sync failed: %v", err)
			return
		}
		proxies, _ := loadAllProxies()
		log.Printf("Sync: Background sync wrote %d proxy route(s) to Caddy.", len(proxies))
	}()
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

	rows, _ := db.Query("SELECT id, owner_email, domain, upstream, upstream_tls, tls_insecure FROM proxies")

	groupsMap := make(map[string][]Proxy)

	for rows.Next() {
		var p Proxy
		var upstreamTLS, tlsInsecure int
		rows.Scan(&p.ID, &p.OwnerEmail, &p.Domain, &p.Upstream, &upstreamTLS, &tlsInsecure)
		p.UpstreamTLS = upstreamTLS != 0
		p.TLSInsecure = tlsInsecure != 0

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
		Email: email, Role: role, ProxyGroups: proxyGroups, Users: users,
		AllowedDomain: allowedBaseDomain, Version: version, SyncStatus: r.URL.Query().Get("sync"),
	})
}

func handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := store.Get(r, "caddy_session")
	if session.Values["role"] != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	status := "ok"
	if err := syncProxiesToCaddy(); err != nil {
		log.Printf("Sync Error: manual resync failed: %v", err)
		status = "error"
	}
	http.Redirect(w, r, "/CaddyCfg/?sync="+status, http.StatusFound)
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
		if _, err := db.Exec("DELETE FROM proxies WHERE id=?", id); err != nil {
			log.Printf("proxy delete DB error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		triggerCaddySync()
	} else {
		subdomain := strings.ToLower(strings.TrimSpace(r.FormValue("subdomain")))
		upstream := strings.TrimSpace(r.FormValue("upstream"))
		upstreamTLS := r.FormValue("upstream_tls") == "1"
		tlsInsecure := r.FormValue("tls_insecure") == "1"
		if tlsInsecure && !upstreamTLS {
			tlsInsecure = false
		}

		upstream = finalizeUpstream(upstream, upstreamTLS)

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

		if _, err := db.Exec(
			"INSERT OR REPLACE INTO proxies (id, owner_email, domain, upstream, upstream_tls, tls_insecure) VALUES (?, ?, ?, ?, ?, ?)",
			newID, email, fullDomain, upstream, boolToInt(upstreamTLS), boolToInt(tlsInsecure),
		); err != nil {
			log.Printf("proxy upsert DB error: %v", err)
			http.Error(w, fmt.Sprintf("database write failed: %v", err), http.StatusInternalServerError)
			return
		}
		triggerCaddySync()
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

	// -http-port overrides PORT when non-empty; precedence: flag > PORT > default 8080.
	httpPortFlag := flag.String("http-port", "", "HTTP listen port (overrides PORT)")
	// -http-bind overrides BIND when non-empty; precedence: flag > BIND > 127.0.0.1.
	httpBindFlag := flag.String("http-bind", "", "HTTP listen bind address (overrides BIND; default 127.0.0.1)")
	versionFlag := flag.Bool("version", false, "print version and exit")
	syncFlag := flag.Bool("sync", false, "sync database proxies to Caddy and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	allowedBaseDomain = os.Getenv("ALLOWED_DOMAIN")
	if allowedBaseDomain == "" { allowedBaseDomain = "co-test-site.com" }
	allowedBaseDomain = strings.TrimPrefix(allowedBaseDomain, ".")

	caddyAPIPort = os.Getenv("CADDY_API_PORT")
	if caddyAPIPort == "" { caddyAPIPort = "2019" }

	initDB()

	if *syncFlag {
		if err := syncProxiesToCaddy(); err != nil {
			log.Fatal("Sync failed:", err)
		}
		proxies, _ := loadAllProxies()
		fmt.Printf("Synced %d proxy route(s) to Caddy.\n", len(proxies))
		os.Exit(0)
	}

	go syncProxies()

	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{Path: "/", MaxAge: 86400 * 7, HttpOnly: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/auth/google", handleGoogleAuth)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/", authRequired(handleDashboard))
	mux.HandleFunc("/proxy", authRequired(handleProxy))
	mux.HandleFunc("/user", authRequired(handleUser))
	mux.HandleFunc("/sync", authRequired(handleSync))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if *httpPortFlag != "" {
		port = *httpPortFlag
	}

	bind := os.Getenv("BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	if *httpBindFlag != "" {
		bind = *httpBindFlag
	}
	addr := net.JoinHostPort(bind, port)

	rootHandler := http.StripPrefix("/CaddyCfg", mux)

	log.Printf("Listening on %s (Mapped to /CaddyCfg)...", addr)
	if err := http.ListenAndServe(addr, rootHandler); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
