package runner

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/xiaoyaochen/flowscan/pkg/crack"
	"github.com/xiaoyaochen/flowscan/pkg/db"
	"github.com/xiaoyaochen/flowscan/pkg/goccm"
	"go.mongodb.org/mongo-driver/bson"
)

type CrackServiceCommand struct {
	MaxThreads     int                       `help:"Max threads" short:"t" default:"20"`
	ThreadManager  *goccm.ConcurrencyManager `kong:"-"`
	ExploreTimeout time.Duration             `short:"x" default:"2s"`
	Debug          bool
	Delay          int           `default:"0"`
	CrackAll       bool          `default:"false"`
	JsonEncoder    *json.Encoder `kong:"-"`
	JsonDecoder    *json.Decoder `kong:"-"`
	crackRunner    *crack.Runner `kong:"-"`
	PortInfo       bool          `help:"print nmap portInfo" short:"p" default:"false"`

	DBOutput   string        `short:"b" help:"db(mongo) to write output results eg.dburl+dbname+collection" default:""`
	JsonOutput string        `short:"j" help:"json to write output results eg.result.json" default:""`
	DB         db.DB         `kong:"-"`
	JsonFile   *json.Encoder `kong:"-"`
}

func (cmd *CrackServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(io.Discard)
	}
	// stdoutEncoder := json.NewEncoder(os.Stdout)
	cmd.JsonDecoder = json.NewDecoder(os.Stdin)
	cmd.JsonEncoder = json.NewEncoder(os.Stdout)
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)
	if cmd.JsonOutput != "" {
		file, err := os.Create(cmd.JsonOutput)
		if err != nil {
			return errors.Wrap(err, "could not create json file")
		}
		defer file.Close()
		cmd.JsonFile = json.NewEncoder(file)
	}
	crackOpt := crack.Options{
		Threads:  cmd.MaxThreads,
		Timeout:  int(cmd.ExploreTimeout),
		Delay:    cmd.Delay,
		CrackAll: cmd.CrackAll,
	}
	var err error
	cmd.crackRunner, err = crack.NewRunner(&crackOpt)
	if err != nil {
		log.Fatal(err)
	}
	if cmd.DBOutput != "" {
		if len(strings.Split(cmd.DBOutput, "+")) != 3 {
			return errors.Errorf("Invalid value for match DBOutput option")
		} else {
			cmd.DB = db.NewMqProducer(cmd.DBOutput)
		}
	}
	// var err error
	defer cmd.ThreadManager.WaitAllDone()
	for {
		ipResult := Result{}
		err := cmd.JsonDecoder.Decode(&ipResult)
		ipaddr := crack.IpAddr{
			Ip:       ipResult.Ip,
			Port:     ipResult.Port,
			Protocol: ipResult.Service}

		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatal(err)
		}
		if cmd.PortInfo {
			cmd.JsonEncoder.Encode(ipResult)
		}
		if crack.SupportProtocols[ipaddr.Protocol] {
			cmd.ThreadManager.Wait()
			go func(ipaddr crack.IpAddr) {
				defer cmd.ThreadManager.Done()
				user := []string{}
				pass := []string{}
				crackresult := cmd.crackRunner.Crack(&ipaddr, user, pass)
				if len(crackresult) > 0 {
					crackr := CrackResult{Ip: ipaddr.Ip, Port: ipaddr.Port, Protocol: ipaddr.Protocol}
					if len(crackresult) >= cmd.MaxThreads && cmd.MaxThreads > 1 {
						crackr.UserPass = []string{}
					} else {
						for _, r := range crackresult {
							crackr.UserPass = append(crackr.UserPass, r.UserPass)
						}
					}
					cmd.JsonEncoder.Encode(crackr)
					if cmd.JsonOutput != "" {
						cmd.JsonFile.Encode(crackr)
					}
					if cmd.DBOutput != "" {
						doc, err := bson.Marshal(crackr)
						hash := md5.Sum([]byte(crackr.Ip + strconv.Itoa(crackr.Port) + crackr.Protocol))
						docid := hex.EncodeToString(hash[:])
						if err != nil {
							gologger.Error().Msgf("Could not Marshal resp: %s\n", err)
						} else {
							err = cmd.DB.Push(docid, doc)
						}
					}
				}
			}(ipaddr)

		}
	}
	return nil
}
