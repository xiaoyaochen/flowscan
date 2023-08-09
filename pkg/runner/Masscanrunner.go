package runner

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/xiaoyaochen/flowscan/pkg/goccm"
	"github.com/xiaoyaochen/flowscan/pkg/gomasscan"
	"github.com/xiaoyaochen/flowscan/pkg/utils"
)

type MasscanServiceCommand struct {
	MaxThreads    int                       `help:"Max threads" short:"t" default:"50"`
	ThreadManager *goccm.ConcurrencyManager `kong:"-"`
	Timeout       time.Duration             `short:"x" default:"10s"`

	Host        string              `help:"host to scan" short:"i" default:""`
	HostFile    string              `help:"host list to scan" short:"l" default:""`
	Port        string              `help:"Port to scan" short:"p" default:""`
	HostList    []string            `kong:"-"`
	DomainIpMap map[string][]string `kong:"-"`
	Rate        int                 `help:"syn scan rate" short:"r" default:"1000"`

	stdinReader   *bufio.Reader      `kong:"-"`
	masscanClient *gomasscan.Scanner `kong:"-"`
	Debug         bool
}

type ipPort struct {
	ip   string
	port int
}

func (cmd *MasscanServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(io.Discard)
	}
	cmd.stdinReader = bufio.NewReaderSize(os.Stdin, 1024*1024)
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)

	if cmd.Port == "" {
		cmd.Port = utils.NmapTop1000
	}

	err := cmd.GetHosts()
	if err != nil {
		log.Fatal(err)
	}
	//初始化gomasscan
	cmd.masscanClient, err = gomasscan.NewScanner()
	if err != nil {
		panic(err)
	}
	cmd.masscanClient.SetRate(cmd.Rate)
	//开放端口处理函数
	var ipports []ipPort
	cmd.masscanClient.HandlerOpen = func(ip string, port int) {
		//输出开放端口
		ipport := ipPort{ip, port}
		if !IsContainIpPort(ipports, ipport) {
			ipports = append(ipports, ipport)
			gologger.Silent().Msgf("%s:%d\n", ipport.ip, ipport.port)
			if cmd.DomainIpMap[ipport.ip] != nil {
				for _, d := range cmd.DomainIpMap[ipport.ip] {
					gologger.Silent().Msgf("%s:%d+%s\n", d, ipport.port, ipport.ip)

				}
			}
		}
	}

	scanPort := utils.ParsePortList(cmd.Port)
	if cmd.HostList != nil {
		cmd.SynScan(cmd.HostList, scanPort)
	}

	defer func() {
		cmd.ThreadManager.WaitAllDone()
		cmd.masscanClient.Done()
	}()
	return nil
}

func (cmd *MasscanServiceCommand) GetHosts() error {
	var hosts string
	if cmd.HostFile != "" {
		fileobj, err := os.Open(cmd.HostFile)
		if err != nil {
			return err
		}
		defer fileobj.Close()
		reader := bufio.NewReader(fileobj)
		var lines []string
		for {
			line, err := reader.ReadString('\n') //注意是字符，换行符。
			line = strings.Replace(line, " ", "", -1)
			// 去除换行符
			line = strings.Replace(line, "\n", "", -1)
			line = strings.Replace(line, "\r", "", -1)
			lines = append(lines, line)
			if err == io.EOF {
				break
			}
			if err != nil { //错误处理
				return err
			}
		}
		hosts = strings.Join(lines, ",")
	} else if cmd.Host != "" {
		hosts = cmd.Host
	}
	var errs []error
	cmd.HostList, cmd.DomainIpMap, errs = utils.ParseIps(hosts)
	for _, err := range errs {
		if err != nil {
			log.Fatal(err)
			return err
		}
	}
	return nil
}

func (cmd *MasscanServiceCommand) SynScan(hosts []string, port_list utils.PortList) error {

	//将IP地址加入筛选范围内
	for _, host := range hosts {
		_ = cmd.masscanClient.Add(host)
	}
	for _, p := range port_list {
		for _, host := range hosts {
			cmd.ThreadManager.Wait()
			go func(host string, port int) {
				cmd.masscanClient.SendSYN(host, port, gomasscan.SYN)
				defer cmd.ThreadManager.Done()
			}(host, p)
		}
	}

	count := len(port_list) * len(hosts)
	// count_last := 0
	for {
		time.Sleep(time.Second)
		count_now := int(cmd.masscanClient.Count())
		// count_last = count_now
		if count_now == count {
			time.Sleep(cmd.Timeout)
			break
		}
	}
	return nil
}

func IsContainIpPort(items []ipPort, item ipPort) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
