package runner

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/xiaoyaochen/flowscan/pkg/db"
	"github.com/xiaoyaochen/flowscan/pkg/goccm"
	"github.com/xiaoyaochen/flowscan/pkg/gonmap"
	"github.com/xiaoyaochen/flowscan/pkg/patchfinger"
	"github.com/xiaoyaochen/flowscan/pkg/utils"
	"github.com/xiaoyaochen/flowscan/pkg/wap"
	"go.mongodb.org/mongo-driver/bson"
)

type NmapServiceCommand struct {
	MaxThreads     int                       `help:"Max threads" short:"t" default:"50"`
	ThreadManager  *goccm.ConcurrencyManager `kong:"-"`
	ExploreTimeout time.Duration             `short:"x" default:"5s"`
	Option         map[string]string         `short:"o"`
	wappalyzer     *wap.Wappalyzer           `kong:"-"`
	patchfinger    *patchfinger.Packjson     `kong:"-"`
	TechDetectFile string                    `help:"the path for wappalyzer technology" short:"w" default:""`
	TechDetect     bool                      `help:"display technology in use based on wappalyzer dataset" short:"d" default:"false"`
	Shiro          bool                      `help:"request for find shiro" default:"true"`
	AllProbe       bool                      `help:"enable Nmap allProbeMap to use" short:"a" default:"false"`
	WafCdnMaxCount int                       `help:"an ip open different port but in the same response max to filt; 0 is close" short:"c" default:"0"`

	HTTPX                     *httpx.HTTPX `kong:"-"`
	RandomAgent               bool         `help:"enable Random User-Agent to use"  default:"true"`
	Retries                   int          `help:"HTTPX Max Retries" short:"r" default:"0"`
	Proxy                     string       `help:"http proxy to use (eg http://127.0.0.1:8080)" default:""`
	FollowRedirects           bool         `help:"HTTPX follow http redirects"  default:"true"`
	FollowHostRedirects       bool         `help:"follow redirects on the same host"  default:"false"`
	MaxRedirects              int          `help:"HTTPX max number of redirects to follow per host" default:"10"`
	TLSGrab                   bool         `help:"perform TLS(SSL) data grabbing" short:"s" default:"false"`
	MaxResponseBodySizeToSave int          `help:"HTTPX max response size to save in bytes"  default:"2147483647"`
	MaxResponseBodySizeToRead int          `help:"HTTPX max response size to read in bytes"  default:"2147483647"`
	Debug                     bool

	DBOutput   string        `short:"b" help:"db(mongo) to write output results eg.dburl+dbname+collection" default:""`
	JsonOutput string        `short:"j" help:"json to write output results eg.result.json" default:""`
	DB         db.DB         `kong:"-"`
	JsonFile   *json.Encoder `kong:"-"`
	Task       string        `help:"Task Name to discriminate results" default:""`
}

func (cmd *NmapServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(io.Discard)
	}
	stdoutEncoder := json.NewEncoder(os.Stdout)
	stdinReader := bufio.NewReaderSize(os.Stdin, 1024*1024)
	if cmd.JsonOutput != "" {
		file, err := os.Create(cmd.JsonOutput)
		if err != nil {
			return errors.Wrap(err, "could not create json file")
		}
		defer file.Close()
		cmd.JsonFile = json.NewEncoder(file)
	}
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)
	var err error

	//是否使用wappalyzer
	if cmd.TechDetect {
		cmd.wappalyzer, err = wap.InitApp(cmd.TechDetectFile)
		if err != nil {
			return errors.Wrap(err, "could not create wappalyzer client")
		}
	}

	if cmd.DBOutput != "" {
		if len(strings.Split(cmd.DBOutput, "+")) != 3 {
			return errors.Errorf("Invalid value for match DBOutput option")
		} else {
			cmd.DB = db.NewMqProducer(cmd.DBOutput)
		}
	}

	//cdn waf 过滤器
	wafop := utils.InitWafCdnOp()

	//初始化Ehole指纹
	cmd.patchfinger, err = patchfinger.NewFingerprint()
	if err != nil {
		return errors.Wrap(err, "could not Init Ehole")
	}

	//HTTPX配置
	DefaultOptions := httpx.Options{
		RandomAgent: cmd.RandomAgent,
		Threads:     cmd.MaxThreads,

		HTTPProxy:                 cmd.Proxy,
		TLSGrab:                   cmd.TLSGrab,
		FollowRedirects:           cmd.FollowRedirects,
		FollowHostRedirects:       cmd.FollowHostRedirects,
		RetryMax:                  cmd.Retries,
		MaxRedirects:              cmd.MaxRedirects,
		MaxResponseBodySizeToSave: int64(cmd.MaxResponseBodySizeToSave),
		MaxResponseBodySizeToRead: int64(cmd.MaxResponseBodySizeToRead),
		Timeout:                   cmd.ExploreTimeout,
	}
	cmd.HTTPX, err = httpx.New(&DefaultOptions)

	defer cmd.ThreadManager.WaitAllDone()
	for {
		bytes, isPrefix, err := stdinReader.ReadLine()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatal(err)
		}
		if isPrefix == true {
			log.Fatal("Event is too big")
		}
		if cmd.WafCdnMaxCount != 0 {
			if !wafop.WcIsPass(string(bytes), cmd.WafCdnMaxCount) {
				continue
			}
		}
		cmd.ThreadManager.Wait()
		go func(input string) {
			log.Printf(input)
			//input输入为host:port、host:port+ip
			//todu：支持url输入
			host, port, ip := cmd.ParseTarget(input)

			//httpx扫描
			result := Result{Ip: ip, Host: host, Port: port}
			var Host string
			if strings.Contains(input, "/") {
				//输入带有/的符号认为是url不做改变
				Host = input
			} else if port == 0 {
				Host = host
			} else {
				Host = host + ":" + strconv.Itoa(port)
			}
			Url, resp, err := cmd.HttpxRequest(Host, result.Ip)
			if err == nil {
				result.Raw = resp.Raw
				result.URL = Url
				result.StatusCode = resp.StatusCode
				result.Title = httpx.ExtractTitle(resp)
				result.TLSData = resp.TLSData
				result.Words = resp.Words
				result.ContentLength = resp.ContentLength
				result.ProbeName = "httpx"
				result.Status = gonmap.Status.String(0x000c3)
				result.Apps, result.Service = cmd.patchfinger.RunFingerprint(resp.Headers, resp.Data, result.Title)
				if cmd.TechDetect {
					matches := cmd.wappalyzer.Fingerprint(resp.Headers, resp.Data, resp.GetChainLastURL())
					for _, match := range matches {
						result.Apps = append(result.Apps, match.Name)
						for _, ct := range match.Categories {
							//将wappalyzer指纹中的操作系统类型提到OperatingSystem字段
							if ct.ID == 28 {
								result.OperatingSystem = match.Name
							}
						}

					}
				}
				result.Apps = utils.ListRemoveDuplicates(result.Apps)
				//补充http协议
				if result.Service == "" {
					if strings.Contains(Url, "https") {
						result.TLS = true
						result.Service = "https"
					} else {
						result.Service = "http"
					}
				}
				//补充端口为0
				if result.Port == 0 {
					parsedURL, err := url.Parse(result.URL)
					if err == nil {
						p := parsedURL.Port()
						if p == "" && strings.Contains(result.URL, "https") {
							result.Port = 443 // 使用默认HTTP端口号
						} else if p == "" && strings.Contains(result.URL, "http") {
							result.Port = 80
						} else {
							result.Port, err = strconv.Atoi(p)
						}
					}
				}
			} else {
				//httpx扫描没识别进行端口扫描
				var scanner = gonmap.New()
				if cmd.AllProbe {
					scanner.OpenDeepIdentify()
				}
				scanner.SetTimeout(cmd.ExploreTimeout)
				if host == ip {
					status, response := scanner.ScanTimeout(host, port, cmd.ExploreTimeout*7)
					result.Status = status.String()
					if response != nil {
						result.Raw = response.Raw
						result.TLS = response.TLS
						result.ProbeName = response.FingerPrint.ProbeName
						result.MatchRegexString = response.FingerPrint.MatchRegexString
						result.Service = response.FingerPrint.Service
						result.ProductName = response.FingerPrint.ProductName
						result.Version = response.FingerPrint.Version
						result.Info = response.FingerPrint.Info
						result.OperatingSystem = response.FingerPrint.OperatingSystem
						result.Hostname = response.FingerPrint.Hostname
						result.DeviceType = response.FingerPrint.DeviceType
						if (strings.Contains(result.Service, "http") && result.TLS) || strings.Contains(result.Service, "https") {
							result.URL = "https://" + result.Host + ":" + strconv.Itoa(result.Port)
						} else if strings.Contains(result.Service, "http") && !result.TLS {
							result.URL = "http://" + result.Host + ":" + strconv.Itoa(result.Port)
						}
					}
				}
			}
			if "Closed" != result.Status && "" != result.Status {
				result.Task = cmd.Task
				stdoutEncoder.Encode(result)
				log.Printf(result.Raw)
				if cmd.WafCdnMaxCount != 0 {
					wafop.WcAccumulate(result.Host, result.Service, result.Title, result.StatusCode, result.Words)
				}
				if cmd.JsonOutput != "" {
					cmd.JsonFile.Encode(result)
				}
				if cmd.DBOutput != "" {
					doc, err := bson.Marshal(result)
					hash := md5.Sum([]byte(result.Host + strconv.Itoa(result.Port) + result.Ip + result.Task))
					docid := hex.EncodeToString(hash[:])
					if err != nil {
						gologger.Error().Msgf("Could not Marshal resp: %s\n", err)
					} else {
						err = cmd.DB.Push(docid, doc)
					}
				}
			}
			cmd.ThreadManager.Done()
		}(string(bytes))
	}
	return nil
}

func (cmd *NmapServiceCommand) ParseTarget(input string) (string, int, string) {
	//判断是否为url
	HostPortIp := strings.Split(input, "+")
	var Host, Ip string
	var Port int
	var err error
	if strings.Contains(HostPortIp[0], "http://") || strings.Contains(HostPortIp[0], "https://") {
		//判断是否输入为url
		parsedURL, err := url.Parse(HostPortIp[0])
		if err == nil {
			Host = parsedURL.Hostname()
			p := parsedURL.Port()

			if p == "" && strings.Contains(HostPortIp[0], "https://") {
				Port = 443 // 使用默认HTTP端口号
			} else if p == "" && strings.Contains(HostPortIp[0], "http://") {
				Port = 80
			} else {
				Port, err = strconv.Atoi(p)
			}
			if len(HostPortIp) == 2 {
				Ip = HostPortIp[1]
			} else {
				ipAddrs, err := net.ResolveIPAddr("ip", Host)
				if err == nil {
					Ip = ipAddrs.IP.String()
				}
			}
		}
	} else {
		var thp string
		if strings.Contains(HostPortIp[0], "/") {
			//解析没有协议头并且有路径的目标，类似127.0.0.1/admin
			thp = strings.Split(HostPortIp[0], "/")[0]
		} else {
			thp = HostPortIp[0]
		}
		//输入为IP端口
		HostPort := strings.Split(thp, ":")
		Host = HostPort[0]
		if len(HostPort) == 2 {
			Port, err = strconv.Atoi(HostPort[1])
		}
		if err != nil {
			log.Println(input, err)
		}
		if len(HostPortIp) == 2 {
			Ip = HostPortIp[1]
		} else {
			ipAddrs, err := net.ResolveIPAddr("ip", Host)
			if err == nil {
				Ip = ipAddrs.IP.String()
			}
		}
	}
	return Host, Port, Ip
}

func (cmd *NmapServiceCommand) HttpxRequest(host string, ip string) (string, *httpx.Response, error) {
	//默认req.Scheme = "https"
	// req, err := retryablehttp.NewRequest(http.MethodGet, input, nil)
	ctx := context.WithValue(context.Background(), "ip", ip) //nolint
	urlx, err := urlutil.ParseURL(host, false)
	req, err := retryablehttp.NewRequestFromURLWithContext(ctx, http.MethodGet, urlx, nil)
	cmd.HTTPX.SetCustomHeaders(req, nil)
	var resp *httpx.Response
	//如果host包含443就默认,否则默认http，如果报错的再更换http(s)
	if strings.Contains(host, "443") {
		req.Scheme = "https"
		resp, err = cmd.HTTPX.Do(req, httpx.UnsafeOptions{})
		if err != nil {
			//req.Scheme = "https"不行就换http
			req.Scheme = "http"
			resp, err = cmd.HTTPX.Do(req, httpx.UnsafeOptions{})
			if err != nil {
				return req.URL.String(), resp, err
			}
		}
	} else {
		req.Scheme = "http"
		resp, err = cmd.HTTPX.Do(req, httpx.UnsafeOptions{})
		if err != nil || strings.Contains(resp.Raw, "The plain HTTP request was sent to HTTPS port") {
			//req.Scheme = "https"不行就换https
			req.Scheme = "https"
			resp, err = cmd.HTTPX.Do(req, httpx.UnsafeOptions{})
			if err != nil {
				return req.URL.String(), resp, err
			}
		}
	}
	if cmd.Shiro {
		if strings.Contains(resp.Raw, "The plain HTTP request was sent to HTTPS port") {
			//如果还是存在The plain HTTP request was sent to HTTPS port，尝试去掉IP
			ctx := context.WithValue(context.Background(), "ip", "") //nolint
			req, err = retryablehttp.NewRequestFromURLWithContext(ctx, http.MethodGet, urlx, nil)
			req.Scheme = "https"
			cmd.HTTPX.SetCustomHeaders(req, nil)
		}
		req.Header.Add("Cookie", "rememberMe=0")
		resp_shiro, err := cmd.HTTPX.Do(req, httpx.UnsafeOptions{})
		if err == nil {
			return req.URL.String(), resp_shiro, nil
		}
	}
	return req.URL.String(), resp, nil
}
