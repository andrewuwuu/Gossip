package chat

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gossip/internal/config"
	"gossip/internal/meshnet"
)

type CLI struct {
	config   *config.Config
	mesh     *meshnet.MeshNet
	peers    *meshnet.PeerManager
	handler  *MessageHandler
	reader   *bufio.Reader
	running  bool
	stopChan chan struct{}
}

func NewCLI(cfg *config.Config) *CLI {
	return &CLI{
		config:   cfg,
		peers:    meshnet.NewPeerManager(),
		reader:   bufio.NewReader(os.Stdin),
		stopChan: make(chan struct{}),
	}
}

func (c *CLI) Run() error {
	c.printBanner()

	mesh, err := meshnet.New(c.config.NodeID)
	if err != nil {
		return fmt.Errorf("failed to initialize mesh: %w", err)
	}
	c.mesh = mesh

	c.handler = NewMessageHandler(c.config.Username, c.config.NodeID)

	if c.config.StoreHistory {
		if err := c.handler.SetHistoryStorage(true, c.config.HistoryPath); err != nil {
			c.printf("Warning: Could not enable history storage: %v\n", err)
		}
	}

	c.handler.SetMessageCallback(func(msg Message) {
		c.displayMessage(msg)
	})

	c.mesh.SetEventCallback(func(event meshnet.Event) {
		c.handleEvent(event)
	})

	if err := c.mesh.Start(c.config.NodePort, c.config.DiscoveryPort); err != nil {
		return fmt.Errorf("failed to start mesh: %w", err)
	}

	c.printf("Node ID: %d | Listening on port %d | Discovery port %d\n",
		c.config.NodeID, c.config.NodePort, c.config.DiscoveryPort)
	c.printf("Type /help for available commands\n\n")

	c.mesh.Discover()

	c.running = true
	return c.inputLoop()
}

func (c *CLI) Stop() {
	c.running = false
	close(c.stopChan)

	if c.mesh != nil {
		c.mesh.Destroy()
	}
}

func (c *CLI) inputLoop() error {
	for c.running {
		c.printPrompt()

		line, err := c.reader.ReadString('\n')
		if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "/") {
			c.handleCommand(line)
		} else {
			c.sendBroadcast(line)
		}
	}

	return nil
}

func (c *CLI) handleCommand(line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])

	switch cmd {
	case "/help", "/h":
		c.printHelp()

	case "/peers", "/p":
		c.listPeers()

	case "/discover", "/d":
		c.mesh.Discover()
		c.printf("Sending discovery broadcast...\n")

	case "/connect", "/c":
		if len(parts) < 3 {
			c.printf("Usage: /connect <address> <port>\n")
			return
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			c.printf("Invalid port: %s\n", parts[2])
			return
		}
		if err := c.mesh.Connect(parts[1], uint16(port)); err != nil {
			c.printf("Failed to connect: %v\n", err)
		} else {
			c.printf("Connecting to %s:%d...\n", parts[1], port)
		}

	case "/msg", "/m":
		if len(parts) < 3 {
			c.printf("Usage: /msg <peer_id> <message>\n")
			return
		}
		peerID, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			c.printf("Invalid peer ID: %s\n", parts[1])
			return
		}
		message := strings.Join(parts[2:], " ")
		c.sendDirectMessage(uint16(peerID), message)

	case "/nick", "/n":
		if len(parts) < 2 {
			c.printf("Usage: /nick <username>\n")
			return
		}
		c.config.Username = parts[1]
		c.printf("Username changed to: %s\n", c.config.Username)

	case "/history":
		limit := 20
		if len(parts) > 1 {
			if l, err := strconv.Atoi(parts[1]); err == nil && l > 0 {
				limit = l
			}
		}
		c.showHistory(limit)

	case "/clear":
		c.clearScreen()

	case "/info", "/i":
		c.showInfo()

	case "/quit", "/q", "/exit":
		c.printf("Goodbye!\n")
		c.running = false

	default:
		c.printf("Unknown command: %s. Type /help for available commands.\n", cmd)
	}
}

func (c *CLI) handleEvent(event meshnet.Event) {
	switch event.Type {
	case meshnet.EventPeerConnected:
		peer := c.peers.AddPeer(event.PeerID, "", 0)
		c.printf("\n[+] Peer connected: %s\n", peer)
		c.printPrompt()

	case meshnet.EventPeerDisconnected:
		peer := c.peers.GetPeer(event.PeerID)
		if peer != nil {
			c.printf("\n[-] Peer disconnected: %s\n", peer)
		} else {
			c.printf("\n[-] Peer disconnected: %d\n", event.PeerID)
		}
		c.peers.RemovePeer(event.PeerID)
		c.printPrompt()

	case meshnet.EventMessageReceived:
		c.handler.HandleIncoming(event.PeerID, event.Username, event.Data)

	case meshnet.EventError:
		c.printf("\n[!] Error: code %d\n", event.ErrorCode)
		c.printPrompt()
	}
}

func (c *CLI) sendBroadcast(message string) {
	if len(message) > 512 {
		c.printf("Message too long (max 512 characters).\n")
		return
	}
	if err := c.mesh.Broadcast(c.config.Username, message); err != nil {
		c.printf("Failed to send: %v\n", err)
		return
	}

	msg := c.handler.CreateOutgoing(0, message, true)
	c.displayOwnMessage(msg)
}

func (c *CLI) sendDirectMessage(peerID uint16, message string) {
	if len(message) > 512 {
		c.printf("Message too long (max 512 characters).\n")
		return
	}
	if err := c.mesh.SendMessage(peerID, c.config.Username, message, false); err != nil {
		c.printf("Failed to send: %v\n", err)
		return
	}

	msg := c.handler.CreateOutgoing(peerID, message, false)
	c.printf("[→ %d] %s\n", peerID, message)
	_ = msg
}

func (c *CLI) displayMessage(msg Message) {
	timestamp := msg.Timestamp.Format("15:04:05")

	if msg.Broadcast {
		fmt.Printf("\n[%s] <%s> %s\n", timestamp, msg.Username, msg.Content)
	} else {
		fmt.Printf("\n[%s] [DM from %s] %s\n", timestamp, msg.Username, msg.Content)
	}

	c.printPrompt()
}

func (c *CLI) displayOwnMessage(msg Message) {
	timestamp := msg.Timestamp.Format("15:04:05")
	fmt.Printf("[%s] <%s> %s\n", timestamp, c.config.Username, msg.Content)
}

func (c *CLI) listPeers() {
	networkPeers := c.mesh.GetPeers()
	c.peers.UpdateFromNetworkPeers(networkPeers)

	peers := c.peers.GetConnectedPeers()

	if len(peers) == 0 {
		c.printf("No peers connected.\n")
		return
	}

	c.printf("Connected peers (%d):\n", len(peers))
	for _, peer := range peers {
		c.printf("  [%d] %s\n", peer.ID, peer)
	}
}

func (c *CLI) showHistory(limit int) {
	messages := c.handler.GetHistory(limit)

	if len(messages) == 0 {
		c.printf("No message history.\n")
		return
	}

	c.printf("Last %d messages:\n", len(messages))
	for _, msg := range messages {
		timestamp := msg.Timestamp.Format("15:04:05")
		if msg.From == c.config.NodeID {
			c.printf("[%s] <%s> %s\n", timestamp, msg.Username, msg.Content)
		} else {
			c.printf("[%s] <%s> %s\n", timestamp, msg.Username, msg.Content)
		}
	}
}

func (c *CLI) showInfo() {
	c.printf("=== Node Info ===\n")
	c.printf("App Name:       %s\n", c.config.AppName)
	c.printf("Node ID:        %d\n", c.config.NodeID)
	c.printf("Username:       %s\n", c.config.Username)
	c.printf("Listen Port:    %d\n", c.config.NodePort)
	c.printf("Discovery Port: %d\n", c.config.DiscoveryPort)
	c.printf("Store History:  %v\n", c.config.StoreHistory)
	c.printf("Connected Peers: %d\n", c.peers.Count())
}

func (c *CLI) printHelp() {
	c.printf(`
Available commands:
  /help, /h          Show this help message
  /peers, /p         List connected peers
  /discover, /d      Send peer discovery broadcast
  /connect, /c       Connect to a peer: /connect <address> <port>
  /msg, /m           Send direct message: /msg <peer_id> <message>
  /nick, /n          Change username: /nick <username>
  /history [n]       Show last n messages (default: 20)
  /info, /i          Show node information
  /clear             Clear the screen
  /quit, /q, /exit   Exit the application

To send a broadcast message, just type your message and press Enter.
`)
}

func (c *CLI) printBanner() {
	fmt.Print(`
 ██████╗  ██████╗ ███████╗███████╗██╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔════╝██║██╔══██╗
██║  ███╗██║   ██║███████╗███████╗██║██████╔╝
██║   ██║██║   ██║╚════██║╚════██║██║██╔═══╝ 
╚██████╔╝╚██████╔╝███████║███████║██║██║     
 ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝     
                    P2P Mesh Chat
`)
}

func (c *CLI) printPrompt() {
	fmt.Printf("[%s] > ", c.config.Username)
}

func (c *CLI) printf(format string, args ...any) {
	fmt.Printf(format, args...)
}

func (c *CLI) clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func init() {
	_ = time.Now
}
