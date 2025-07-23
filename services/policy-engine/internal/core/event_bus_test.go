package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

type mockEventHandler struct {
	mu              sync.Mutex
	receivedEvents  []*framework.Event
	handleEventFunc func(ctx context.Context, event *framework.Event) error
}

func (m *mockEventHandler) HandleEvent(ctx context.Context, event *framework.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.receivedEvents = append(m.receivedEvents, event)
	
	if m.handleEventFunc != nil {
		return m.handleEventFunc(ctx, event)
	}
	return nil
}

func (m *mockEventHandler) EventTypes() []string {
	return []string{"test.event", "framework.started"}
}

func (m *mockEventHandler) getReceivedEvents() []*framework.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	events := make([]*framework.Event, len(m.receivedEvents))
	copy(events, m.receivedEvents)
	return events
}

func TestEventBus(t *testing.T) {
	logger := logging.NewLogger("debug")
	
	t.Run("Initialize", func(t *testing.T) {
		eb := NewEventBus(logger)
		err := eb.Initialize(context.Background())
		assert.NoError(t, err)
	})
	
	t.Run("StartStop", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		
		err = eb.Start(ctx)
		assert.NoError(t, err)
		
		// Try to start again
		err = eb.Start(ctx)
		assert.Error(t, err)
		
		err = eb.Stop(ctx)
		assert.NoError(t, err)
		
		// Try to stop again
		err = eb.Stop(ctx)
		assert.Error(t, err)
	})
	
	t.Run("Subscribe", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		handler := &mockEventHandler{}
		
		// Subscribe to event
		err = eb.Subscribe("test.event", handler)
		assert.NoError(t, err)
		
		// Try to subscribe same handler again
		err = eb.Subscribe("test.event", handler)
		assert.Error(t, err)
		
		// Subscribe to different event
		err = eb.Subscribe("another.event", handler)
		assert.NoError(t, err)
		
		// Check subscriber count
		count := eb.GetSubscriberCount("test.event")
		assert.Equal(t, 1, count)
	})
	
	t.Run("Unsubscribe", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		handler := &mockEventHandler{}
		
		// Subscribe
		err = eb.Subscribe("test.event", handler)
		require.NoError(t, err)
		
		// Unsubscribe
		err = eb.Unsubscribe("test.event", handler)
		assert.NoError(t, err)
		
		// Try to unsubscribe again
		err = eb.Unsubscribe("test.event", handler)
		assert.Error(t, err)
		
		// Check subscriber count
		count := eb.GetSubscriberCount("test.event")
		assert.Equal(t, 0, count)
	})
	
	t.Run("PublishEvent", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		handler := &mockEventHandler{}
		err = eb.Subscribe("test.event", handler)
		require.NoError(t, err)
		
		// Publish event
		event := &framework.Event{
			Type:   "test.event",
			Source: "test",
			Data: map[string]interface{}{
				"message": "test message",
			},
		}
		
		err = eb.Publish(event)
		assert.NoError(t, err)
		
		// Wait for event to be processed
		time.Sleep(100 * time.Millisecond)
		
		// Check if handler received event
		events := handler.getReceivedEvents()
		require.Len(t, events, 1)
		assert.Equal(t, "test.event", events[0].Type)
		assert.NotEmpty(t, events[0].ID)
		assert.False(t, events[0].Timestamp.IsZero())
	})
	
	t.Run("MultipleHandlers", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		handler1 := &mockEventHandler{}
		handler2 := &mockEventHandler{}
		
		err = eb.Subscribe("test.event", handler1)
		require.NoError(t, err)
		err = eb.Subscribe("test.event", handler2)
		require.NoError(t, err)
		
		// Publish event
		event := &framework.Event{
			Type:   "test.event",
			Source: "test",
		}
		
		err = eb.Publish(event)
		assert.NoError(t, err)
		
		// Wait for events to be processed
		time.Sleep(100 * time.Millisecond)
		
		// Both handlers should receive the event
		assert.Len(t, handler1.getReceivedEvents(), 1)
		assert.Len(t, handler2.getReceivedEvents(), 1)
	})
	
	t.Run("WildcardSubscription", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		handler := &mockEventHandler{}
		err = eb.Subscribe("*", handler)
		require.NoError(t, err)
		
		// Publish different types of events
		events := []*framework.Event{
			{Type: "test.event1", Source: "test"},
			{Type: "test.event2", Source: "test"},
			{Type: "framework.started", Source: "test"},
		}
		
		for _, event := range events {
			err = eb.Publish(event)
			require.NoError(t, err)
		}
		
		// Wait for events to be processed
		time.Sleep(100 * time.Millisecond)
		
		// Handler should receive all events
		receivedEvents := handler.getReceivedEvents()
		assert.Len(t, receivedEvents, 3)
	})
	
	t.Run("EventHandlerPanic", func(t *testing.T) {
		eb := NewEventBus(logger)
		ctx := context.Background()
		
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		err = eb.Start(ctx)
		require.NoError(t, err)
		defer eb.Stop(ctx)
		
		// Handler that panics
		panicHandler := &mockEventHandler{
			handleEventFunc: func(ctx context.Context, event *framework.Event) error {
				panic("test panic")
			},
		}
		
		// Handler that works normally
		normalHandler := &mockEventHandler{}
		
		err = eb.Subscribe("test.event", panicHandler)
		require.NoError(t, err)
		err = eb.Subscribe("test.event", normalHandler)
		require.NoError(t, err)
		
		// Publish event
		event := &framework.Event{
			Type:   "test.event",
			Source: "test",
		}
		
		err = eb.Publish(event)
		assert.NoError(t, err)
		
		// Wait for events to be processed
		time.Sleep(100 * time.Millisecond)
		
		// Normal handler should still receive the event
		assert.Len(t, normalHandler.getReceivedEvents(), 1)
	})
	
	t.Run("EventQueueFull", func(t *testing.T) {
		eb := NewEventBus(logger)
		eb.bufferSize = 1 // Small buffer for testing
		eb.eventChannel = make(chan *framework.Event, 1)
		
		ctx := context.Background()
		err := eb.Initialize(ctx)
		require.NoError(t, err)
		
		// Don't start workers to fill up the queue
		eb.running = true
		
		// Fill the queue
		err = eb.Publish(&framework.Event{Type: "test1", Source: "test"})
		assert.NoError(t, err)
		
		// This should fail due to full queue
		err = eb.Publish(&framework.Event{Type: "test2", Source: "test"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "event channel full")
	})
}

func TestEventBusPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	logger := logging.NewLogger("error") // Less verbose for performance test
	eb := NewEventBus(logger)
	ctx := context.Background()
	
	err := eb.Initialize(ctx)
	require.NoError(t, err)
	err = eb.Start(ctx)
	require.NoError(t, err)
	defer eb.Stop(ctx)
	
	// Create a handler that counts events
	var receivedCount int64
	var mu sync.Mutex
	handler := &mockEventHandler{
		handleEventFunc: func(ctx context.Context, event *framework.Event) error {
			mu.Lock()
			receivedCount++
			mu.Unlock()
			return nil
		},
	}
	
	err = eb.Subscribe("perf.test", handler)
	require.NoError(t, err)
	
	// Publish many events
	eventCount := 10000
	start := time.Now()
	
	for i := 0; i < eventCount; i++ {
		event := &framework.Event{
			Type:   "perf.test",
			Source: "perf-test",
			Data: map[string]interface{}{
				"index": i,
			},
		}
		err := eb.Publish(event)
		require.NoError(t, err)
	}
	
	publishDuration := time.Since(start)
	
	// Wait for all events to be processed
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := receivedCount
		mu.Unlock()
		
		if count >= int64(eventCount) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	processingDuration := time.Since(start)
	
	mu.Lock()
	finalCount := receivedCount
	mu.Unlock()
	
	assert.Equal(t, int64(eventCount), finalCount, "All events should be processed")
	
	publishRate := float64(eventCount) / publishDuration.Seconds()
	processingRate := float64(eventCount) / processingDuration.Seconds()
	
	t.Logf("Published %d events in %v (%.0f events/sec)", eventCount, publishDuration, publishRate)
	t.Logf("Processed %d events in %v (%.0f events/sec)", eventCount, processingDuration, processingRate)
	
	// Basic performance assertions
	assert.Greater(t, publishRate, 10000.0, "Should publish at least 10k events/sec")
	assert.Greater(t, processingRate, 5000.0, "Should process at least 5k events/sec")
}