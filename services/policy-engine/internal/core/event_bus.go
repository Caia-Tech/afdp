package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// EventBus manages event distribution within the framework
type EventBus struct {
	logger       *logging.Logger
	mu           sync.RWMutex
	subscribers  map[string][]framework.EventHandler
	eventChannel chan *framework.Event
	workers      int
	bufferSize   int
	running      bool
	wg           sync.WaitGroup
	stopCh       chan struct{}
}

// NewEventBus creates a new event bus instance
func NewEventBus(logger *logging.Logger) *EventBus {
	return &EventBus{
		logger:       logger,
		subscribers:  make(map[string][]framework.EventHandler),
		eventChannel: make(chan *framework.Event, 10000), // Buffer for events
		workers:      10, // Number of worker goroutines
		bufferSize:   10000,
		stopCh:       make(chan struct{}),
	}
}

// Initialize prepares the event bus
func (eb *EventBus) Initialize(ctx context.Context) error {
	eb.logger.Info("Initializing event bus...")
	
	// Pre-create common event type slices to avoid allocations
	commonEventTypes := []string{
		"framework.started",
		"framework.stopped",
		"plugin.registered",
		"plugin.unregistered",
		"plugin.started",
		"plugin.stopped",
		"configuration.reloaded",
		"policy.evaluated",
		"decision.made",
		"error.occurred",
	}
	
	eb.mu.Lock()
	for _, eventType := range commonEventTypes {
		if _, exists := eb.subscribers[eventType]; !exists {
			eb.subscribers[eventType] = make([]framework.EventHandler, 0)
		}
	}
	eb.mu.Unlock()
	
	return nil
}

// Start begins event processing
func (eb *EventBus) Start(ctx context.Context) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	
	if eb.running {
		return fmt.Errorf("event bus is already running")
	}
	
	eb.logger.Info("Starting event bus...", "workers", eb.workers)
	eb.running = true
	
	// Start worker goroutines
	for i := 0; i < eb.workers; i++ {
		eb.wg.Add(1)
		go eb.eventWorker(i)
	}
	
	return nil
}

// Stop shuts down the event bus
func (eb *EventBus) Stop(ctx context.Context) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	
	if !eb.running {
		return fmt.Errorf("event bus is not running")
	}
	
	eb.logger.Info("Stopping event bus...")
	eb.running = false
	
	// Signal workers to stop
	close(eb.stopCh)
	
	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		eb.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		eb.logger.Info("All event workers stopped")
	case <-ctx.Done():
		eb.logger.Warn("Event bus stop timed out")
		return ctx.Err()
	}
	
	// Process any remaining events
	remaining := len(eb.eventChannel)
	if remaining > 0 {
		eb.logger.Warn("Discarding remaining events", "count", remaining)
	}
	
	return nil
}

// Subscribe registers an event handler for specific event types
func (eb *EventBus) Subscribe(eventType string, handler framework.EventHandler) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}
	
	// Check if handler is already subscribed
	handlers := eb.subscribers[eventType]
	for _, h := range handlers {
		if h == handler {
			return fmt.Errorf("handler already subscribed to event type %s", eventType)
		}
	}
	
	eb.subscribers[eventType] = append(handlers, handler)
	eb.logger.Debug("Handler subscribed to event", "eventType", eventType)
	
	return nil
}

// Unsubscribe removes an event handler
func (eb *EventBus) Unsubscribe(eventType string, handler framework.EventHandler) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	
	handlers, exists := eb.subscribers[eventType]
	if !exists {
		return fmt.Errorf("no subscribers for event type %s", eventType)
	}
	
	// Find and remove the handler
	for i, h := range handlers {
		if h == handler {
			// Remove handler by swapping with last element and truncating
			handlers[i] = handlers[len(handlers)-1]
			eb.subscribers[eventType] = handlers[:len(handlers)-1]
			eb.logger.Debug("Handler unsubscribed from event", "eventType", eventType)
			return nil
		}
	}
	
	return fmt.Errorf("handler not found for event type %s", eventType)
}

// Publish sends an event to all subscribers
func (eb *EventBus) Publish(event *framework.Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	
	// Add event ID if not present
	if event.ID == "" {
		event.ID = generateEventID()
	}
	
	// Set timestamp if not present
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	// Check if event bus is running
	eb.mu.RLock()
	running := eb.running
	eb.mu.RUnlock()
	
	if !running {
		return fmt.Errorf("event bus is not running")
	}
	
	// Try to send event to channel (non-blocking)
	select {
	case eb.eventChannel <- event:
		return nil
	default:
		eb.logger.Warn("Event channel full, dropping event", 
			"eventType", event.Type,
			"eventID", event.ID,
		)
		return fmt.Errorf("event channel full")
	}
}

// eventWorker processes events from the channel
func (eb *EventBus) eventWorker(workerID int) {
	defer eb.wg.Done()
	
	eb.logger.Debug("Event worker started", "workerID", workerID)
	
	for {
		select {
		case event, ok := <-eb.eventChannel:
			if !ok {
				eb.logger.Debug("Event channel closed, worker stopping", "workerID", workerID)
				return
			}
			eb.processEvent(event)
			
		case <-eb.stopCh:
			eb.logger.Debug("Event worker stopping", "workerID", workerID)
			return
		}
	}
}

// processEvent handles a single event
func (eb *EventBus) processEvent(event *framework.Event) {
	eb.mu.RLock()
	handlers := eb.subscribers[event.Type]
	// Also get handlers for wildcard subscriptions
	wildcardHandlers := eb.subscribers["*"]
	eb.mu.RUnlock()
	
	// Create a combined list of handlers
	allHandlers := make([]framework.EventHandler, 0, len(handlers)+len(wildcardHandlers))
	allHandlers = append(allHandlers, handlers...)
	allHandlers = append(allHandlers, wildcardHandlers...)
	
	if len(allHandlers) == 0 {
		eb.logger.Debug("No handlers for event", "eventType", event.Type)
		return
	}
	
	// Process event with each handler
	for _, handler := range allHandlers {
		// Create timeout context for each handler
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		
		// Handle event in separate goroutine to prevent blocking
		go func(h framework.EventHandler, e *framework.Event) {
			defer cancel()
			defer func() {
				if r := recover(); r != nil {
					eb.logger.Error("Event handler panic", 
						"eventType", e.Type,
						"eventID", e.ID,
						"panic", r,
					)
				}
			}()
			
			start := time.Now()
			if err := h.HandleEvent(ctx, e); err != nil {
				eb.logger.Error("Event handler error",
					"eventType", e.Type,
					"eventID", e.ID,
					"error", err,
					"duration", time.Since(start),
				)
			} else {
				eb.logger.Debug("Event handled successfully",
					"eventType", e.Type,
					"eventID", e.ID,
					"duration", time.Since(start),
				)
			}
		}(handler, event)
	}
}

// GetSubscriberCount returns the number of subscribers for an event type
func (eb *EventBus) GetSubscriberCount(eventType string) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	
	return len(eb.subscribers[eventType])
}

// GetEventTypes returns all event types with subscribers
func (eb *EventBus) GetEventTypes() []string {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	
	types := make([]string, 0, len(eb.subscribers))
	for eventType := range eb.subscribers {
		types = append(types, eventType)
	}
	return types
}

// GetQueueSize returns the current number of events in the queue
func (eb *EventBus) GetQueueSize() int {
	return len(eb.eventChannel)
}

// generateEventID creates a unique event ID
func generateEventID() string {
	// Simple implementation - in production, use UUID or similar
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), randInt())
}

// randInt generates a random integer (simplified for example)
func randInt() int {
	return int(time.Now().UnixNano() % 1000000)
}