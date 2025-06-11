package libadb

import (
	"fmt"
	"sync"
)

var ChannelMapInstance *ChannelMap = NewChannelMap()

type ChannelMap struct {
	mu          sync.RWMutex
	data        map[string]chan Message
	mappingList map[uint32]uint32 // 存储本地连接的映射关系，键为连接ID，值为通道的指针或其他相关信息，根据实际情况调整类型
}

func NewChannelMap() *ChannelMap {
	return &ChannelMap{
		data:        make(map[string]chan Message),
		mappingList: make(map[uint32]uint32),
	}
}
func (cm *ChannelMap) GetChannel(id uint32, remote bool) chan Message {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if remote {
		if localId, exists := cm.mappingList[id]; exists {
			id = localId
		} else {
			return nil
		}
	}
	key := fmt.Sprintf("local:%d", id)
	if ch, exists := cm.data[key]; exists {
		return ch
	}
	return nil
}

func (cm *ChannelMap) Bind(local uint32, remote uint32) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.mappingList[remote] = local
}
func (cm *ChannelMap) AddChannel(localId uint32, chanel chan Message) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	key := fmt.Sprintf("local:%d", localId)
	if chanel != nil {
		cm.data[key] = chanel
	} else {
		cm.data[key] = make(chan Message, 20)
	}
	return nil
}
func (cm *ChannelMap) DeleteChannel(localId uint32) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	key := fmt.Sprintf("local:%d", localId)
	if ch, exists := cm.data[key]; exists {
		if !isClosed(ch) {
			close(ch)
		}
		cleanupChan(ch)
		delete(cm.data, key)
		return
	}
	return
}
func (cm *ChannelMap) CloseAllAndClear() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	// 关闭所有通道
	for key, ch := range cm.data {
		if !isClosed(ch) {
			close(ch)
		}
		cleanupChan(ch)
		delete(cm.data, key)
	}
	cm.mappingList = make(map[uint32]uint32) // 方式1：重建映射（更高效）
}

func isClosed(ch chan Message) bool {
	select {
	case _, ok := <-ch:
		if !ok {
			return true
		}
	default:
	}
	return false
}

func cleanupChan(ch chan Message) {
	var isClear = true
	for isClear {
		select {
		case _, ok := <-ch:
			if !ok {
				isClear = false
			}
			break
		default:
			isClear = false
		}
	}
}
