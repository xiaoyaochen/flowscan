package runner

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/xiaoyaochen/flowscan/pkg/goccm"
	"github.com/xiaoyaochen/flowscan/pkg/utils"
)

type TcpscanServiceCommand struct {
	MaxThreads    int                       `help:"Max threads" short:"t" default:"500"`
	ThreadManager *goccm.ConcurrencyManager `kong:"-"`
	Timeout       time.Duration             `short:"x" default:"10s"`

	Host        string              `help:"host to scan" short:"i" default:""`
	HostFile    string              `help:"host list to scan" short:"l" default:""`
	Port        string              `help:"Port to scan" short:"p" default:""`
	HostList    []string            `kong:"-"`
	DomainIpMap map[string][]string `kong:"-"`

	stdinReader *bufio.Reader `kong:"-"`
	Debug       bool
}

func (cmd *TcpscanServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(ioutil.Discard)
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

	scanPort := utils.ParsePortList(cmd.Port)
	if cmd.HostList != nil {
		cmd.TcpScan(cmd.HostList, scanPort)
	}

	defer cmd.ThreadManager.WaitAllDone()
	return nil
}

func (cmd *TcpscanServiceCommand) GetHosts() error {
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

func (cmd *TcpscanServiceCommand) TcpScan(hosts []string, port_list utils.PortList) error {

	//将IP地址加入筛选范围内
	for _, p := range port_list {
		for _, host := range hosts {
			cmd.ThreadManager.Wait()
			go func(host string, port int) {
				address := host + ":" + strconv.Itoa(port)
				conn, err := net.DialTimeout("tcp", address, cmd.Timeout)
				if err == nil {
					// 端口连接成功，表示端口已开放
					conn.Close()
					gologger.Silent().Msgf("%s:%d\n", host, port)
					if cmd.DomainIpMap[host] != nil {
						for _, d := range cmd.DomainIpMap[host] {
							gologger.Silent().Msgf("%s:%d+%s\n", d, port, host)

						}
					}
				}
				defer cmd.ThreadManager.Done()
			}(host, p)
		}
	}

	return nil
}
