// 新增文件 client_pool.go
package core

import (
	cmap "github.com/orcaman/concurrent-map/v2"
	"log"
	"sync"
	"time"
)

type ClientPoolManager struct {
	queue   *PriorityQueue[pqItem]
	mu      sync.Mutex
	trigger chan struct{}
}

type pqItem struct {
	Key      string
	ExpireAt time.Time
}

func NewClientPoolManager() *ClientPoolManager {
	compareFunc := func(a, b pqItem) bool {
		return a.ExpireAt.Before(b.ExpireAt)
	}
	return &ClientPoolManager{
		queue:   NewPriorityQueue[pqItem](compareFunc),
		trigger: make(chan struct{}, 1),
	}
}

func (m *ClientPoolManager) Update(client *EasyConnectClient, key string) {
	expireAt := time.Now().Add(client.IdleTimeout)
	if client.MaxLifetime < client.IdleTimeout {
		expireAt = client.createdAt.Add(client.MaxLifetime)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.queue.Push(pqItem{Key: key, ExpireAt: expireAt})

	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func (m *ClientPoolManager) StartCleaner(pool cmap.ConcurrentMap[string, *EasyConnectClient]) {
	go func() {
		for {
			select {
			case <-m.trigger:
				m.cleanExpired(pool)
			case <-time.After(5 * time.Second):
				m.cleanExpired(pool)
			}
		}
	}()
}

func (m *ClientPoolManager) cleanExpired(pool cmap.ConcurrentMap[string, *EasyConnectClient]) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		item, exists := m.queue.Peek()
		if !exists || item.ExpireAt.After(now) {
			break
		}

		poppedItem, _ := m.queue.Pop()
		if client, ok := pool.Get(poppedItem.Key); ok {
			if client.IsExpired() {
				log.Println("空闲超时，正在关闭上游客户端")
				client.Close()
				pool.Remove(poppedItem.Key)
			} else {
				newExpire := time.Now().Add(client.IdleTimeout)
				if client.createdAt.Add(client.MaxLifetime).Before(newExpire) {
					newExpire = client.createdAt.Add(client.MaxLifetime)
				}
				m.queue.Push(pqItem{
					Key:      poppedItem.Key,
					ExpireAt: newExpire,
				})
			}
		}
	}
}
