package chat

import (
	"fmt"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type TUI struct {
	cli      *CLI
	viewport viewport.Model
	input    textinput.Model
	width    int
	height   int
	program  *tea.Program
	content  string
	mu       sync.Mutex
}

type tuiLineMsg struct {
	line string
}

func NewTUI(cli *CLI) *TUI {
	input := textinput.New()
	input.Placeholder = "Type message or /command"
	input.Focus()
	input.CharLimit = 512
	input.Prompt = "> "

	vp := viewport.New(0, 0)
	initial := "Gossip Mesh Chat\n"
	vp.SetContent(initial)

	return &TUI{
		cli:      cli,
		viewport: vp,
		input:    input,
		content:  initial,
	}
}

func (t *TUI) Run() error {
	program := tea.NewProgram(t)
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
	switch m := msg.(type) {
	case tuiLineMsg:
		line := strings.TrimSpace(m.line)
		if line != "" {
			t.mu.Lock()
			if !strings.HasSuffix(t.content, "\n") {
				t.content += "\n"
			}
			t.content += line + "\n"
			t.viewport.SetContent(t.content)
			t.viewport.GotoBottom()
			t.mu.Unlock()
		}
		return t, nil
	case tea.WindowSizeMsg:
		t.width = m.Width
		t.height = m.Height
		inputHeight := 3
		t.viewport.Width = m.Width
		t.viewport.Height = m.Height - inputHeight
		return t, nil

	case tea.KeyMsg:
		switch m.String() {
		case "ctrl+c", "esc":
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
	}

	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	return t, cmd
}

func (t *TUI) View() string {
	content := t.viewport.View()
	input := t.input.View()
	remaining := 512 - len(t.input.Value())
	if remaining < 0 {
		remaining = 0
	}
	footer := fmt.Sprintf("%d chars left", remaining)
	return fmt.Sprintf("%s\n%s\n%s", content, input, footer)
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

func (t *TUI) handleInput(text string) {
	if strings.HasPrefix(text, "/") {
		if t.cli != nil {
			t.cli.handleCommand(text)
		}
		return
	}

	if t.cli != nil {
		t.cli.sendBroadcast(text)
	}
}
