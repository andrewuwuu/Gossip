package chat

import (
	"fmt"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles for the TUI
var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			Bold(true)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#353533"))

	statusKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#A3A29C")).
			Padding(0, 1)

	statusValStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#353533")).
			Padding(0, 1)

	msgSenderStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#04B575")).
			Bold(true)

	msgSelfStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5F87")).
			Bold(true)
)

type TUI struct {
	cli       *CLI
	viewport  viewport.Model
	input     textinput.Model
	program   *tea.Program
	content   string
	mu        sync.Mutex
	ready     bool
	width     int
	height    int
	peerCount int
	status    string
}

type tuiLineMsg struct {
	line string
}

type tuiQuitMsg struct{}

type tuiStatusMsg struct {
	status    string
	peerCount int
}

func NewTUI(cli *CLI) *TUI {
	input := textinput.New()
	input.Placeholder = "Type message or /command"
	input.Focus()
	input.CharLimit = 512
	input.Prompt = "➤ "
	input.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))

	vp := viewport.New(0, 0)
	// Render banner with color
	banner := BannerStyle.Render(BannerText)
	initial := banner + "\n"
	vp.SetContent(initial)

	return &TUI{
		cli:      cli,
		viewport: vp,
		input:    input,
		content:  initial,
		status:   "Ready",
	}
}

func (t *TUI) Run() error {
	// Use AltScreen to access full terminal and proper mouse support
	program := tea.NewProgram(t, tea.WithAltScreen(), tea.WithMouseCellMotion())
	t.program = program
	_, err := program.Run()
	return err
}

func (t *TUI) Init() tea.Cmd {
	t.mu.Lock()
	t.viewport.SetContent(t.content)
	t.mu.Unlock()
	return textinput.Blink
}

func (t *TUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch m := msg.(type) {
	case tuiQuitMsg:
		if t.cli != nil {
			t.cli.Stop()
		}
		return t, tea.Quit

	case tuiLineMsg:
		// Format line with some basic coloring if it looks like a message
		line := strings.TrimSpace(m.line)
		if line != "" {
			t.mu.Lock()
			if !strings.HasSuffix(t.content, "\n") {
				t.content += "\n"
			}

			// Capture if we are at bottom BEFORE adding content
			atBottom := t.viewport.AtBottom()

			t.content += line + "\n"
			t.viewport.SetContent(t.content)

			// Only auto-scroll if we were already at bottom
			if atBottom {
				t.viewport.GotoBottom()
			}
			t.mu.Unlock()
		}
		return t, nil

	case tuiStatusMsg:
		t.status = m.status
		t.peerCount = m.peerCount
		return t, nil

	case tea.KeyMsg:
		switch m.String() {
		case "ctrl+c":
			if t.cli != nil {
				t.cli.Stop()
			}
			return t, tea.Quit
		case "enter":
			text := strings.TrimSpace(t.input.Value())
			t.input.SetValue("")
			if text != "" {
				t.handleInput(text)
			}
			return t, nil
		}

	case tea.WindowSizeMsg:
		t.width = m.Width
		t.height = m.Height
		t.ready = true

		// Calculate layout
		headerHeight := lipgloss.Height(t.headerView())
		footerHeight := lipgloss.Height(t.footerView())
		verticalMarginHeight := headerHeight + footerHeight

		if !t.ready {
			// Since this program is using the full size of the terminal,
			// we need to wait for the first window size msg to initialize
			// the viewport.
			t.viewport = viewport.New(m.Width, m.Height-verticalMarginHeight)
			t.viewport.SetContent(t.content)
		} else {
			t.viewport.Width = m.Width
			t.viewport.Height = m.Height - verticalMarginHeight
		}
		t.input.Width = m.Width - 5 // leave room for prompt

		if t.content != "" {
			t.viewport.SetContent(t.content)
			t.viewport.GotoBottom() // Keep scrolled to bottom on resize
		}
	}

	t.viewport, cmd = t.viewport.Update(msg)
	cmds = append(cmds, cmd)

	t.input, cmd = t.input.Update(msg)
	cmds = append(cmds, cmd)

	return t, tea.Batch(cmds...)
}

func (t *TUI) View() string {
	if !t.ready {
		return "\n  Initializing..."
	}
	return fmt.Sprintf("%s\n%s\n%s", t.headerView(), t.viewport.View(), t.footerView())
}

func (t *TUI) headerView() string {
	title := headerStyle.Render(fmt.Sprintf(" Gossip Node: %d ", t.cli.config.NodeID))
	// Add more info if width allows
	line := strings.Repeat("─", max(0, t.width-lipgloss.Width(title)))
	return lipgloss.JoinHorizontal(lipgloss.Center, title, line)
}

func (t *TUI) footerView() string {
	peers := statusValStyle.Render(fmt.Sprintf("%d", t.peerCount))
	status := statusValStyle.Render(t.status)

	bar := lipgloss.JoinHorizontal(lipgloss.Top,
		statusKeyStyle.Render("PEERS"),
		peers,
		statusKeyStyle.Render("STATUS"),
		status,
	)

	// Fill rest of line
	w := lipgloss.Width(bar)
	if t.width > w {
		bar += statusBarStyle.Render(strings.Repeat(" ", t.width-w))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		bar,
		t.input.View(),
	)
}

func (t *TUI) AppendLine(line string) {
	if line == "" {
		return
	}
	if t.program != nil {
		t.program.Send(tuiLineMsg{line: line})
		return
	}
	t.mu.Lock()
	if !strings.HasSuffix(t.content, "\n") {
		t.content += "\n"
	}
	t.content += line + "\n"
	t.mu.Unlock()
}

func (t *TUI) UpdateStatus(status string, peerCount int) {
	if t.program != nil {
		t.program.Send(tuiStatusMsg{status: status, peerCount: peerCount})
	}
}

func (t *TUI) Quit() {
	if t.program != nil {
		t.program.Send(tuiQuitMsg{})
	}
}

func (t *TUI) handleInput(text string) {
	if t.cli == nil {
		return
	}

	if strings.HasPrefix(text, "/") {
		t.cli.handleCommand(text)
	} else {
		t.cli.sendBroadcast(text)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
