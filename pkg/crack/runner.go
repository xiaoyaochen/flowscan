package crack

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xiaoyaochen/flowscan/pkg/crack/plugins"

	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Threads  int
	Timeout  int
	Delay    int
	CrackAll bool

	UserMap      map[string][]string
	CommonPass   []string
	TemplatePass []string
}

type Runner struct {
	options *Options
}

func NewRunner(options *Options) (*Runner, error) {
	if len(options.UserMap) == 0 {
		options.UserMap = userMap
	}
	if len(options.CommonPass) == 0 {
		options.CommonPass = commonPass
	}
	if len(options.TemplatePass) == 0 {
		options.TemplatePass = templatePass
	}
	return &Runner{
		options: options,
	}, nil
}

type Result struct {
	Addr     string
	Protocol string
	UserPass string
}

type IpAddr struct {
	Ip       string
	Port     int
	Protocol string
}

func (r *Runner) Run(addrs []*IpAddr, userDict []string, passDict []string) (results []*Result) {
	for _, addr := range addrs {
		results = append(results, r.Crack(addr, userDict, passDict)...)
	}
	return
}

func (r *Runner) Crack(addr *IpAddr, userDict []string, passDict []string) (results []*Result) {
	gologger.Info().Msgf("开始爆破: %v:%v %v", addr.Ip, addr.Port, addr.Protocol)

	var tasks []plugins.Service
	var taskHash string
	taskHashMap := map[string]bool{}
	// GenTask
	if len(userDict) == 0 {
		userDict = r.options.UserMap[addr.Protocol]
	}
	if len(passDict) == 0 {
		passDict = append(passDict, r.options.TemplatePass...)
		passDict = append(passDict, r.options.CommonPass...)
	}
	for _, user := range userDict {
		for _, pass := range passDict {
			// 替换{user}
			pass = strings.ReplaceAll(pass, "{user}", user)
			// 任务去重
			taskHash = Md5(fmt.Sprintf("%v%v%v%v%v", addr.Ip, addr.Port, addr.Protocol, user, pass))
			if taskHashMap[taskHash] {
				continue
			}
			taskHashMap[taskHash] = true
			tasks = append(tasks, plugins.Service{
				Ip:       addr.Ip,
				Port:     addr.Port,
				Protocol: addr.Protocol,
				User:     user,
				Pass:     pass,
				Timeout:  r.options.Timeout,
			})
		}
	}
	// RunTask
	stopMap := cmap.New[string]()
	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	taskChan := make(chan plugins.Service, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				addrStr := fmt.Sprintf("%v:%v", addr.Ip, addr.Port)
				userPass := fmt.Sprintf("%v:%v", task.User, task.Pass)
				addrHash := Md5(addrStr)
				// 判断是否已经停止爆破
				if stopMap.Has(addrHash) {
					wg.Done()
					continue
				}
				gologger.Debug().Msgf("[trying] %v", userPass)
				scanFunc := plugins.ScanFuncMap[task.Protocol]
				resp, err := scanFunc(&task)
				switch resp {
				case plugins.CrackSuccess:
					if !r.options.CrackAll {
						stopMap.Set(addrHash, "ok")
					}
					gologger.Debug().Msgf("%v -> %v %v", addr.Protocol, addrStr, userPass)
					mutex.Lock()
					results = append(results, &Result{
						Addr:     addrStr,
						Protocol: addr.Protocol,
						UserPass: userPass,
					})
					mutex.Unlock()
				case plugins.CrackError:
					stopMap.Set(addrHash, "ok")
					gologger.Debug().Msgf("crack err, %v", err)
				case plugins.CrackFail:
				}
				if r.options.Delay > 0 {
					time.Sleep(time.Duration(r.options.Delay) * time.Second)
				}
				wg.Done()
			}
		}()
	}

	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	gologger.Info().Msgf("爆破结束: %v:%v %v", addr.Ip, addr.Port, addr.Protocol)

	return
}

func Md5(s string) string {
	m := md5.New()
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}
