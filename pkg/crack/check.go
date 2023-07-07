package crack

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// CheckAlive 存活检测
func (r *Runner) CheckAlive(addrs []*IpAddr) (results []*IpAddr) {
	// RunTask
	rwMutex := &sync.RWMutex{}
	wg := &sync.WaitGroup{}
	taskChan := make(chan *IpAddr, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				if r.conn(task) {
					rwMutex.Lock()
					results = append(results, task)
					rwMutex.Unlock()
				}
				wg.Done()
			}
		}()
	}

	for _, task := range addrs {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	return
}

// conn 建立tcp连接
func (r *Runner) conn(ipAddr *IpAddr) (alive bool) {
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ipAddr.Ip, ipAddr.Port), time.Duration(r.options.Timeout)*time.Second)
	if err == nil {
		alive = true
	}
	return
}
