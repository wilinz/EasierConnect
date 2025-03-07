package core

import (
	"container/heap"
	"sync"
)

// PriorityQueue 泛型优先队列（最小堆）
type PriorityQueue[T any] struct {
	heap     *genericHeap[T]
	lock     sync.Mutex
	notifyCh chan struct{} // 用于通知有新元素插入
	compare  func(a, b T) bool
}

// 内部堆实现
type genericHeap[T any] struct {
	data    []T
	compare func(a, b T) bool
}

func (h *genericHeap[T]) Len() int           { return len(h.data) }
func (h *genericHeap[T]) Less(i, j int) bool { return h.compare(h.data[i], h.data[j]) }
func (h *genericHeap[T]) Swap(i, j int)      { h.data[i], h.data[j] = h.data[j], h.data[i] }
func (h *genericHeap[T]) Push(x any)         { h.data = append(h.data, x.(T)) }
func (h *genericHeap[T]) Pop() any {
	n := len(h.data)
	item := h.data[n-1]
	h.data = h.data[:n-1]
	return item
}

// 创建新队列（需传入比较函数）
func NewPriorityQueue[T any](compare func(a, b T) bool) *PriorityQueue[T] {
	h := &genericHeap[T]{compare: compare}
	heap.Init(h)
	return &PriorityQueue[T]{
		heap:     h,
		compare:  compare,
		notifyCh: make(chan struct{}, 1),
	}
}

// 添加元素（线程安全）
func (pq *PriorityQueue[T]) Push(item T) {
	pq.lock.Lock()
	defer pq.lock.Unlock()
	heap.Push(pq.heap, item)

	// 非阻塞通知
	select {
	case pq.notifyCh <- struct{}{}:
	default:
	}
}

// 弹出最小元素（线程安全）
func (pq *PriorityQueue[T]) Pop() (T, bool) {
	pq.lock.Lock()
	defer pq.lock.Unlock()
	if pq.heap.Len() == 0 {
		var zero T
		return zero, false
	}
	return heap.Pop(pq.heap).(T), true
}

// 查看最小元素（不弹出，线程安全）
func (pq *PriorityQueue[T]) Peek() (T, bool) {
	pq.lock.Lock()
	defer pq.lock.Unlock()
	if pq.heap.Len() == 0 {
		var zero T
		return zero, false
	}
	return pq.heap.data[0], true
}

// 获取队列长度（线程安全）
func (pq *PriorityQueue[T]) Len() int {
	pq.lock.Lock()
	defer pq.lock.Unlock()
	return pq.heap.Len()
}

// 更新元素（需重新调整堆）
func (pq *PriorityQueue[T]) Update(index int, newItem T) {
	pq.lock.Lock()
	defer pq.lock.Unlock()
	if index < 0 || index >= pq.heap.Len() {
		return
	}
	pq.heap.data[index] = newItem
	heap.Fix(pq.heap, index)
}

// 等待通知通道（用于外部监听队列变化）
func (pq *PriorityQueue[T]) NotifyChannel() <-chan struct{} {
	return pq.notifyCh
}
