package tui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/runtime"
)

type runtimeEventsMsg struct {
	events []protocol.Event
}

type runtimeBridgeClosedMsg struct{}

type runtimeEventBridge struct {
	mu      sync.Mutex
	batches [][]protocol.Event
	wake    chan struct{}
	done    chan struct{}
	closed  bool
}

func subscribeRuntimeEvents(rt runtime.Runtime) (*runtimeEventBridge, func()) {
	if rt == nil {
		return nil, func() {}
	}
	bridge := &runtimeEventBridge{
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	unsubscribe := rt.Subscribe(bridge.enqueue)
	return bridge, func() {
		unsubscribe()
		bridge.close()
	}
}

func (b *runtimeEventBridge) enqueue(events []protocol.Event) {
	if b == nil || len(events) == 0 {
		return
	}
	batch := append([]protocol.Event(nil), events...)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.batches = append(b.batches, batch)
	b.signalLocked()
	b.mu.Unlock()
}

func (b *runtimeEventBridge) waitCmd() tea.Cmd {
	if b == nil {
		return nil
	}
	return func() tea.Msg {
		select {
		case <-b.wake:
			if events, ok := b.pop(); ok {
				return runtimeEventsMsg{events: events}
			}
		case <-b.done:
		}
		return runtimeBridgeClosedMsg{}
	}
}

func (b *runtimeEventBridge) pop() ([]protocol.Event, bool) {
	if b == nil {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.batches) == 0 {
		return nil, false
	}
	events := b.batches[0]
	b.batches[0] = nil
	b.batches = b.batches[1:]
	b.signalLocked()
	return events, true
}

func (b *runtimeEventBridge) popNow() ([]protocol.Event, bool) {
	if b == nil {
		return nil, false
	}
	select {
	case <-b.wake:
	default:
	}
	return b.pop()
}

func (b *runtimeEventBridge) signalLocked() {
	if len(b.batches) == 0 || b.closed {
		return
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *runtimeEventBridge) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.done)
	}
	b.mu.Unlock()
}
