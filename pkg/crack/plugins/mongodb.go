package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func MongodbCrack(serv *Service) (int, error) {
	// 未授权
	if res, err := MongodbUnAuth(serv); res != -1 {
		return res, err
	}
	// 口令爆破
	// 设置连接选项
	addr := fmt.Sprintf("mongodb://%v:%v", serv.Ip, serv.Port)
	clientOptions := options.Client().ApplyURI(addr).SetAuth(options.Credential{
		Username: serv.User,
		Password: serv.Pass,
	})

	// 创建客户端
	client, err := mongo.NewClient(clientOptions)
	if err != nil {
		fmt.Println(err)
		return CrackError, err
	}

	// 连接数据库
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(serv.Timeout))
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		return CrackError, err
	}
	defer client.Disconnect(ctx)

	// 检查连接是否成功
	err = client.Ping(ctx, nil)
	if err != nil {
		return CrackFail, nil
	}

	return CrackSuccess, nil
}

var senddata = []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}

func MongodbUnAuth(serv *Service) (int, error) {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(serv.Timeout)*time.Second)
	if err != nil {
		return CrackError, err
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(serv.Timeout) * time.Second))
	if err != nil {
		return CrackError, err
	}
	defer conn.Close()
	_, err = conn.Write(senddata)
	if err != nil {
		return CrackError, err
	}
	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		return CrackError, err
	}
	text := string(buf[0:count])
	if strings.Contains(text, "totalLinesWritten") {
		return CrackSuccess, nil
	}
	return -1, nil
}
