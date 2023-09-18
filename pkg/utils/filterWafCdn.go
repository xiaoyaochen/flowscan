package utils

import (
	"crypto/md5"
	"fmt"
	"strings"
	"sync"
)

type WafCdnOp struct {
	WafCdnHashMap     map[[16]byte]int
	WhitePortlist     []string
	WhiteIplist       []string
	BlackProtocollist []string
	WafCdnIpMap       map[string]int
}

var mu sync.Mutex

func InitWafCdnOp() *WafCdnOp {
	op := WafCdnOp{WafCdnHashMap: map[[16]byte]int{},
		WhitePortlist:     []string{"", "80", "443"},
		WhiteIplist:       []string{},
		BlackProtocollist: []string{"", "http", "https"},
		WafCdnIpMap:       map[string]int{},
	}

	return &op
}

func (Op WafCdnOp) WcAccumulate(ip string, protocol string, title string, statusCode int, lenth int) {
	//cdn、waf 主要体现在web或者一些没有识别的协议上
	//如果有识别到非BlackProtocollist上的协议可认为该IP比较少概率是waf或者cdn
	if !Listcontains(Op.BlackProtocollist, protocol) {
		Op.WhiteIplist = append(Op.WhiteIplist, ip)
		return
	}
	hash := md5.Sum([]byte(fmt.Sprintf("%s%s%s%d%d", ip, protocol, title, statusCode, lenth)))
	mu.Lock()
	defer mu.Unlock()
	//端口返回hash相同累计
	Op.WafCdnHashMap[hash] += 1
	if Op.WafCdnHashMap[hash] > Op.WafCdnIpMap[ip] {
		Op.WafCdnIpMap[ip] = Op.WafCdnHashMap[hash]
	}
}

func (Op WafCdnOp) WcIsPass(input string, count int) bool {
	//判断该IP是否可扫描
	temp := strings.Split(input, ":")
	ip := temp[0]
	var port string
	//解析IP端口
	if len(temp) == 2 {
		port = strings.Split(temp[1], "+")[0]
	} else {
		port = ""
	}
	//在IP白名单或者端口白名单的就直接扫描
	if Listcontains(Op.WhiteIplist, ip) || Listcontains(Op.WhitePortlist, port) {
		return true
	}
	//IP在BlackProtocollist中的累计次数如果超过count就会过滤掉
	if Op.WafCdnIpMap[ip] > count {
		return false
	}
	return true
}
