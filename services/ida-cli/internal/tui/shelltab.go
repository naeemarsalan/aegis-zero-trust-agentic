package tui

// shelltab.go — embedded interactive terminal tab (Shell, tab index 4).
//
// Design:
//   - A vt10x virtual terminal emulates the remote PTY output. The TUI writes
//     PTY bytes into it; View() renders the screen grid as a plain-text string.
//   - Input keystrokes are encoded by HandleKey and written to a stdin pipe that
//     feeds the openshell.Connect goroutine.
//   - Resize events are forwarded through a buffered channel to pty.Setsize so
//     the remote shell gets SIGWINCH equivalents.
//   - Redraw notifications are sent (non-blocking) on a chan struct{}; the
//     bubbletea event loop polls this via waitForShellRedraw so new output
//     triggers a re-render without any goroutine calling Program.Send directly.
//
// Concurrency:
//   - The vt10x Terminal interface guards its own state with an internal mutex
//     (Lock/Unlock). All writes come from a single goroutine (the PTY reader
//     inside openshell.Connect). All reads come from the bubbletea main goroutine
//     in View(). We surround reads/writes with Lock/Unlock as required by the
//     vt10x API.
//   - started, connected, err, sandboxName are written only on the bubbletea
//     main goroutine (via Start/Stop). They are read on the same goroutine in
//     View(). No additional mutex is needed for those fields.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	vt10x "github.com/hinshun/vt10x"

	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/openshell"
	"git.arsalan.io/anaeem/nvidia-ida/services/ida-cli/internal/tui/theme"
)

// shellRedrawMsg is sent by waitForShellRedraw when the PTY writer notifies
// that new terminal output is available and the view should be re-rendered.
// It carries the session generation (so stale-session events are ignored) and
// the channel it came from (so the loop re-issues on the SAME channel, keeping
// each session's reader alive until that session's exit is delivered).
type shellRedrawMsg struct {
	gen uint64
	ch  chan shellEvent
}

// shellExitMsg is sent when the Connect goroutine exits (clean or error).
type shellExitMsg struct {
	name string
	err  error
	gen  uint64
}

// shellEvent is the union type written by the goroutine onto the event channel.
// Either redraw is set (normal output arrived) or exit is set (goroutine done).
type shellEvent struct {
	gen    uint64
	redraw bool
	exit   *shellExitMsg
}

// waitForShellRedraw returns a tea.Cmd that blocks on the event channel and
// returns either shellRedrawMsg (to re-render) or shellExitMsg (goroutine done).
// The caller re-issues this Cmd on every shellRedrawMsg to keep the loop alive.
func waitForShellRedraw(ch chan shellEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil // channel closed — session ended; no more events
		}
		if ev.exit != nil {
			return *ev.exit
		}
		return shellRedrawMsg{gen: ev.gen, ch: ch}
	}
}

// ShellTab is the bubbletea sub-model for the embedded terminal tab.
type ShellTab struct {
	// vt emulator — receives raw PTY bytes and exposes a rendered screen.
	vt     vt10x.Terminal
	vtCols int
	vtRows int

	// session state (mutated only on the bubbletea goroutine)
	sandboxName string
	started     bool
	connected   bool
	err         error
	// gen identifies the current session. Incremented on every Start; events
	// tagged with an older gen (from a session that was Stop()'d) are ignored by
	// the App so a stale goroutine cannot clobber the live session's state.
	gen uint64

	// I/O wiring
	stdinR   *io.PipeReader // read end — passed to openshell.Connect
	stdinW   *io.PipeWriter // write end — HandleKey writes here
	resizeCh chan [2]uint16  // forwarded to openshell.Connect resize param
	eventCh  chan shellEvent // carries redraw & exit signals to the Cmd loop
	cancel   context.CancelFunc
}

// NewShellTab constructs an idle ShellTab sized to the given pane dimensions.
func NewShellTab(width, height int) ShellTab {
	cols, rows := vtDimensions(width, height)
	return ShellTab{
		vt:     vt10x.New(vt10x.WithSize(cols, rows)),
		vtCols: cols,
		vtRows: rows,
	}
}

// SetSize resizes the virtual terminal emulator and, if connected, pushes a
// resize event to the PTY.
//
// Note: vt10x.Resize acquires its own internal mutex, so we must NOT hold the
// vt lock ourselves when calling it.
func (s *ShellTab) SetSize(width, height int) {
	cols, rows := vtDimensions(width, height)
	if cols == s.vtCols && rows == s.vtRows {
		return
	}
	s.vtCols = cols
	s.vtRows = rows
	// Resize manages its own lock internally.
	s.vt.Resize(cols, rows)
	if s.connected && s.resizeCh != nil {
		// Non-blocking send; if the channel is full we drop the event.  The next
		// resize will catch up (the remote side only needs the latest size).
		select {
		case s.resizeCh <- [2]uint16{uint16(cols), uint16(rows)}:
		default:
		}
	}
}

// Start begins a new openshell.Connect session for the named sandbox. It is a
// no-op if a session is already running for the same sandbox.
//
// Start returns a tea.Cmd that should be batched by the caller to kick off
// the waitForShellRedraw loop.
func (s *ShellTab) Start(osh *openshell.Client, sandboxName string) tea.Cmd {
	if osh == nil {
		s.err = fmt.Errorf("gateway unreachable: no openshell client")
		return nil
	}
	// Already running for the same sandbox — do nothing.
	if s.started && s.sandboxName == sandboxName {
		return nil
	}
	// Clean up any previous session before starting a new one.
	s.stop()

	s.sandboxName = sandboxName
	s.started = true
	s.connected = false
	s.err = nil
	s.gen++ // new session generation
	gen := s.gen

	// Reset the vt emulator to a blank screen (Resize manages its own lock).
	s.vt.Resize(s.vtCols, s.vtRows)

	// Create new I/O plumbing.
	s.stdinR, s.stdinW = io.Pipe()
	s.resizeCh = make(chan [2]uint16, 4)
	// eventCh carries both redraw events (new PTY output) and the final exit
	// event; buffered so the goroutine doesn't block on non-blocking sends.
	s.eventCh = make(chan shellEvent, 8)

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	eventCh := s.eventCh // capture for closure

	// vtWriter wraps the vt emulator Write so it also sends a non-blocking
	// redraw notification after each write.
	vtW := &vtWriter{vt: s.vt, notify: eventCh, gen: gen}

	go func() {
		// No client-side ownership check: the gateway authorises `sandbox connect`
		// per-RPC. No PodForSandbox: openshell resolves the target itself.
		// Emit an initial resize so the remote PTY gets the right window size.
		select {
		case s.resizeCh <- [2]uint16{uint16(s.vtCols), uint16(s.vtRows)}:
		default:
		}
		execErr := osh.Connect(ctx, sandboxName, s.stdinR, vtW, s.resizeCh)
		sendExit(eventCh, shellExitMsg{name: sandboxName, err: execErr, gen: gen})
	}()

	return waitForShellRedraw(s.eventCh)
}

// Stop terminates the current session (if any). It closes the stdin pipe and
// cancels the context, causing the Connect goroutine to exit.
func (s *ShellTab) Stop() {
	s.stop()
}

// stop is the internal implementation shared by Stop and Start.
func (s *ShellTab) stop() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.stdinW != nil {
		_ = s.stdinW.Close()
		s.stdinW = nil
	}
	if s.stdinR != nil {
		_ = s.stdinR.Close()
		s.stdinR = nil
	}
	// Do NOT close eventCh here. The Connect goroutine is the SOLE sender and may
	// still emit a final exit event after the context is cancelled; closing the
	// channel from here would panic ("send on closed channel"). We simply
	// abandon the reference — the goroutine's channel and its reader are GC'd
	// once both drop it. Stale events that arrive later carry an old gen and are
	// ignored by the App.
	s.eventCh = nil
	s.resizeCh = nil
	s.started = false
	s.connected = false
}

// HandleExitMsg processes a shellExitMsg (emitted by the Connect goroutine)
// so the App can update connection state.
func (s *ShellTab) HandleExitMsg(msg shellExitMsg) {
	s.connected = false
	s.started = false
	if msg.err != nil && !isContextCanceled(msg.err) {
		s.err = msg.err
	}
}

// HandleKey encodes the bubbletea key message to terminal byte sequences and
// writes them to the stdin pipe. Returns false if the key should be consumed by
// the Shell tab (i.e. not propagated to the global key handler), true if it is
// the escape key (ctrl+b) that should return to the dashboard.
//
// Note: ctrl+b is the "escape back to dashboard" shortcut.
func (s *ShellTab) HandleKey(msg tea.KeyMsg) (escape bool) {
	if msg.String() == "ctrl+b" {
		return true
	}
	if s.stdinW == nil {
		return false
	}
	b := keyToBytes(msg)
	if len(b) > 0 {
		_, _ = s.stdinW.Write(b) // pipe; errors mean the session died — ignore
	}
	return false
}

// View renders the virtual terminal screen as a string. The output is sized to
// the pane dimensions. States: no sandbox selected, connecting, error, live.
func (s ShellTab) View() string {
	var b strings.Builder

	title := "Shell"
	if s.sandboxName != "" {
		title += " — " + s.sandboxName
	}
	b.WriteString(theme.SectionTitleStyle.Render(title) + "\n\n")

	switch {
	case s.sandboxName == "":
		b.WriteString(theme.MutedStyle.Render("  Select a sandbox, then press 5 or tab to Shell.") + "\n")
		b.WriteString(theme.MutedStyle.Render("  ctrl+b returns to the dashboard.") + "\n")

	case s.err != nil:
		b.WriteString(theme.ErrorStyle.Render("Error: "+s.err.Error()) + "\n")
		b.WriteString(theme.MutedStyle.Render("  ctrl+b: back to dashboard") + "\n")

	case s.started && !s.connected:
		// Goroutine is running (connecting) but exec stream not yet established.
		b.WriteString(theme.MutedStyle.Render(fmt.Sprintf("  connecting to %s…", s.sandboxName)) + "\n")

	default:
		// Render the vt10x screen.
		// String() acquires the internal mutex itself — do NOT hold the lock here.
		screen := s.vt.String()
		// vt10x.State.String() returns rows*cols runes + '\n' per row.
		b.WriteString(screen)
	}

	hint := theme.MutedStyle.Render("ctrl+b: back to dashboard")
	return theme.MainPanelStyle.
		Width(s.vtCols + 4). // +4 for border+padding
		Render(b.String() + "\n" + hint)
}

// ---------------------------------------------------------------------------
// key encoding
// ---------------------------------------------------------------------------

// keyToBytes encodes a bubbletea KeyMsg into the byte sequence that should be
// sent to the remote shell's stdin.
func keyToBytes(msg tea.KeyMsg) []byte {
	// Ctrl+A..Ctrl+Z → bytes 1..26.
	// bubbletea reports these as "ctrl+a" … "ctrl+z".
	s := msg.String()
	if len(s) == 6 && strings.HasPrefix(s, "ctrl+") {
		ch := s[5]
		if ch >= 'a' && ch <= 'z' {
			return []byte{ch - 'a' + 1}
		}
	}

	switch msg.Type {
	case tea.KeyRunes:
		// Printable runes — encode as UTF-8.
		buf := make([]byte, utf8.UTFMax*len(msg.Runes))
		n := 0
		for _, r := range msg.Runes {
			n += utf8.EncodeRune(buf[n:], r)
		}
		return buf[:n]

	case tea.KeySpace:
		return []byte{' '}
	case tea.KeyEnter:
		return []byte{'\r'}
	case tea.KeyBackspace:
		return []byte{0x7f}
	case tea.KeyTab:
		return []byte{'\t'}
	case tea.KeyEsc:
		return []byte{0x1b}
	case tea.KeyUp:
		return []byte{0x1b, '[', 'A'}
	case tea.KeyDown:
		return []byte{0x1b, '[', 'B'}
	case tea.KeyRight:
		return []byte{0x1b, '[', 'C'}
	case tea.KeyLeft:
		return []byte{0x1b, '[', 'D'}
	case tea.KeyHome:
		return []byte{0x1b, '[', 'H'}
	case tea.KeyEnd:
		return []byte{0x1b, '[', 'F'}
	case tea.KeyPgUp:
		return []byte{0x1b, '[', '5', '~'}
	case tea.KeyPgDown:
		return []byte{0x1b, '[', '6', '~'}
	case tea.KeyDelete:
		return []byte{0x1b, '[', '3', '~'}
	}
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// vtDimensions converts a pane pixel-width/height to VT terminal cols/rows,
// clamping to sane minimums.
func vtDimensions(width, height int) (cols, rows int) {
	cols = width - 4  // subtract border+padding from MainPanelStyle
	rows = height - 6 // subtract title + hint + borders
	if cols < 10 {
		cols = 10
	}
	if rows < 4 {
		rows = 4
	}
	return cols, rows
}

// vtWriter is an io.Writer that forwards bytes to the vt10x terminal and then
// sends a non-blocking redraw notification on the event channel.
type vtWriter struct {
	vt     vt10x.Terminal
	notify chan<- shellEvent
	gen    uint64
}

func (w *vtWriter) Write(p []byte) (int, error) {
	// vt10x.Write acquires its own internal mutex — do NOT hold the public lock.
	n, err := w.vt.Write(p)
	// Non-blocking redraw notification; drop if channel is full.
	select {
	case w.notify <- shellEvent{redraw: true, gen: w.gen}:
	default:
	}
	return n, err
}

// sendExit delivers the session's final exit event. Unlike redraw notifications
// (which are droppable), the exit MUST be delivered so the App can release the
// session — so this is a blocking send. It is safe: the channel is never closed
// (the goroutine is the sole sender), it is buffered, and the App keeps a reader
// alive on each channel (re-issuing waitForShellRedraw on the channel each event
// came from) until that channel's exit is consumed.
func sendExit(ch chan<- shellEvent, msg shellExitMsg) {
	ch <- shellEvent{exit: &msg, gen: msg.gen}
}

// isContextCanceled returns true if err wraps context.Canceled or
// context.DeadlineExceeded (i.e. the session ended because Stop() was called,
// not because of a real error).
func isContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "context canceled") ||
		strings.Contains(s, "context deadline exceeded")
}
