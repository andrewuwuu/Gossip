package chat

import "github.com/charmbracelet/lipgloss"

const (
	// ANSI Color codes for CLI
	BannerColorCLI = "\033[92m" // Light Green
	ResetColorCLI  = "\033[0m"

	BannerText = `
 ██████╗  ██████╗ ███████╗███████╗██╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔════╝██║██╔══██╗
██║  ███╗██║   ██║███████╗███████╗██║██████╔╝
██║   ██║██║   ██║╚════██║╚════██║██║██╔═══╝ 
╚██████╔╝╚██████╔╝███████║███████║██║██║     
 ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝     
                    P2P Mesh Chat
`
)

// TUI Styles
var (
	BannerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575")). // Matches CLI Light Green roughly
		Bold(true)
)
