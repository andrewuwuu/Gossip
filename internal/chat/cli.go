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
	ui       *TUI
}

func NewCLI(cfg *config.Config) *CLI {
	cli := &CLI{
		config:   cfg,
		peers:    meshnet.NewPeerManager(),
		reader:   bufio.NewReader(os.Stdin),
		stopChan: make(chan struct{}),
	}
	cli.ui = NewTUI(cli)
	cli.ui.AppendLine(fmt.Sprintf("Node ID: %d | Listening on port %d | Discovery port %d", cfg.NodeID, cfg.NodePort, cfg.DiscoveryPort))
	cli.ui.AppendLine("Type /help for available commands")
	return cli
}

func (c *CLI) Run() error {
	if c.ui == nil {
		c.printBanner()
	}

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

	if c.ui == nil {
		c.printf("Node ID: %d | Listening on port %d | Discovery port %d\n",
			c.config.NodeID, c.config.NodePort, c.config.DiscoveryPort)
		c.printf("Type /help for available commands\n\n")
	}

	c.mesh.Discover()

	c.running = true
	if c.ui != nil {
		return c.ui.Run()
	}
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
		c.printf("Goodbye!")
		c.running = false
		if c.ui != nil {
			c.ui.Quit()
		}

	default:
		c.printf("Unknown command: %s. Type /help for available commands.\n", cmd)
	}
}

func (c *CLI) handleEvent(event meshnet.Event) {
	switch event.Type {
	case meshnet.EventPeerConnected:
		peer := c.peers.AddPeer(event.PeerID, "", 0)
		c.printf("[+] Peer connected: %s", peer)
		c.printPrompt()

	case meshnet.EventPeerDisconnected:
		peer := c.peers.GetPeer(event.PeerID)
		if peer != nil {
			c.printf("[-] Peer disconnected: %s", peer)
		} else {
			c.printf("[-] Peer disconnected: %d", event.PeerID)
		}
		c.peers.RemovePeer(event.PeerID)
		c.printPrompt()

	case meshnet.EventMessageReceived:
		c.handler.HandleIncoming(event.PeerID, event.Username, event.Data)

	case meshnet.EventError:
		c.printf("[!] Error: code %d", event.ErrorCode)
		c.printPrompt()
	}
}

func (c *CLI) sendBroadcast(message string) {
	if len(message) > 512 {
		c.printf("Message too long (max 512 characters).")
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
		c.printf("Message too long (max 512 characters).")
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
	if c.ui != nil {
		if msg.Broadcast {
			c.ui.AppendLine(fmt.Sprintf("<%s> %s", msg.Username, msg.Content))
		} else {
			c.ui.AppendLine(fmt.Sprintf("[DM from %s] %s", msg.Username, msg.Content))
		}
		return
	}

	timestamp := msg.Timestamp.Format("15:04:05")

	if msg.Broadcast {
		fmt.Printf("\n[%s] <%s> %s\n", timestamp, msg.Username, msg.Content)
	} else {
		fmt.Printf("\n[%s] [DM from %s] %s\n", timestamp, msg.Username, msg.Content)
	}

	c.printPrompt()
}

func (c *CLI) displayOwnMessage(msg Message) {
	if c.ui != nil {
		c.ui.AppendLine(fmt.Sprintf("<%s> %s", c.config.Username, msg.Content))
		return
	}

	timestamp := msg.Timestamp.Format("15:04:05")
	fmt.Printf("[%s] <%s> %s\n", timestamp, c.config.Username, msg.Content)
}

func (c *CLI) listPeers() {
	networkPeers := c.mesh.GetPeers()
	c.peers.UpdateFromNetworkPeers(networkPeers)

	peers := c.peers.GetConnectedPeers()

	if len(peers) == 0 {
		c.printf("No peers connected.")
		return
	}

	c.printf("Connected peers (%d):", len(peers))
	for _, peer := range peers {
		c.printf("  [%d] %s", peer.ID, peer)
	}
}

func (c *CLI) showHistory(limit int) {
	messages := c.handler.GetHistory(limit)

	if len(messages) == 0 {
		c.printf("No message history.")
		return
	}

	c.printf("Last %d messages:", len(messages))
	for _, msg := range messages {
		timestamp := msg.Timestamp.Format("15:04:05")
		if msg.From == c.config.NodeID {
			c.printf("[%s] <%s> %s", timestamp, msg.Username, msg.Content)
		} else {
			c.printf("[%s] <%s> %s", timestamp, msg.Username, msg.Content)
		}
	}
}

func (c *CLI) showInfo() {
	c.printf("=== Node Info ===")
	c.printf("App Name:       %s", c.config.AppName)
	c.printf("Node ID:        %d", c.config.NodeID)
	c.printf("Username:       %s", c.config.Username)
	c.printf("Listen Port:    %d", c.config.NodePort)
	c.printf("Discovery Port: %d", c.config.DiscoveryPort)
	c.printf("Store History:  %v", c.config.StoreHistory)
	c.printf("Connected Peers: %d", c.peers.Count())
}

func (c *CLI) printHelp() {
	c.printf("Available commands:")
	c.printf("  /help, /h          Show this help message")
	c.printf("  /peers, /p         List connected peers")
	c.printf("  /discover, /d      Send peer discovery broadcast")
	c.printf("  /connect, /c       Connect to a peer: /connect <address> <port>")
	c.printf("  /msg, /m           Send direct message: /msg <peer_id> <message>")
	c.printf("  /nick, /n          Change username: /nick <username>")
	c.printf("  /history [n]       Show last n messages (default: 20)")
	c.printf("  /info, /i          Show node information")
	c.printf("  /clear             Clear the screen")
	c.printf("  /quit, /q, /exit   Exit the application")
	c.printf("To send a broadcast message, just type your message and press Enter.")
}

func (c *CLI) printBanner() {
	if c.ui != nil {
		return
	}
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
	if c.ui != nil {
		return
	}
	fmt.Printf("[%s] > ", c.config.Username)
}

func (c *CLI) printf(format string, args ...any) {
	if c.ui != nil {
		line := strings.TrimRight(fmt.Sprintf(format, args...), "\n")
		c.ui.AppendLine(line)
		return
	}
	fmt.Printf(format, args...)
}

func (c *CLI) clearScreen() {
	if c.ui != nil {
		return
	}
	fmt.Print("\033[H\033[2J")
}

func init() {
	_ = time.Now
}
