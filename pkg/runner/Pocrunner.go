package runner

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/xiaoyaochen/flowscan/pkg/db"
	"github.com/xiaoyaochen/flowscan/pkg/goccm"
	utl "github.com/xiaoyaochen/flowscan/pkg/utils"
	"github.com/zan8in/afrog/pkg/catalog"
	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/core"
	"github.com/zan8in/afrog/pkg/gopoc"
	"github.com/zan8in/afrog/pkg/poc"
	http2 "github.com/zan8in/afrog/pkg/protocols/http"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/afrog/pocs"
	"go.mongodb.org/mongo-driver/bson"
)

var options = &config.Options{}
var lock sync.Mutex

type PocServiceCommand struct {
	MaxThreads     int                       `help:"Max threads" short:"t" default:"20"`
	ThreadManager  *goccm.ConcurrencyManager `kong:"-"`
	ExploreTimeout time.Duration             `short:"x" default:"2s"`
	Debug          bool
	Search         string        `help:"search PoC by keyword , eg: -s tomcat,phpinfo" short:"s" default:""`
	Finger         bool          `help:"filter PoC by Finger" default:"True"`
	Severity       string        `help:"pocs to run based on severity. Possible values: info, low, medium, high, critical, unknown" short:"S" default:""`
	UpdatePocs     bool          `help:"update afrog-pocs" short:"u" default:"false"`
	PrintPocs      bool          `help:"print afrog-pocs list" short:"l" default:"false"`
	PocsFilePath   string        `help:"afrog-pocs PocsFilePath" short:"f" default:""`
	JsonEncoder    *json.Encoder `kong:"-"`
	JsonDecoder    *json.Decoder `kong:"-"`
	PortInfo       bool          `help:"print nmap portInfo" short:"p" default:"false"`

	DBOutput   string        `short:"b" help:"db(mongo) to write output results eg.dburl+dbname+collection" default:""`
	JsonOutput string        `short:"j" help:"json to write output results eg.result.json" default:""`
	DB         db.DB         `kong:"-"`
	JsonFile   *json.Encoder `kong:"-"`

	Pocs []poc.Poc `kong:"-"`
}

func (cmd *PocServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(io.Discard)
	}

	if cmd.PrintPocs {
		plist, err := pocs.PrintPocs()
		if err != nil {
			return err
		}
		for _, v := range plist {
			fmt.Println(v)
		}
		fmt.Println("PoC count: ", len(plist))
		return nil
	}
	if cmd.UpdatePocs {
		upgrade := upgrade.New()
		upgrade.IsUpdatePocs = cmd.UpdatePocs
		upgrade.UpgradeAfrogPocs()

		printPathLog(upgrade)
		return nil
	}

	cfg, err0 := config.New()
	if err0 != nil {
		return err0
	}

	options.Config = cfg
	options.Search = cmd.Search
	options.Severity = cmd.Severity
	options.ApiCallBack = func(result any) {
		lock.Lock()
		r := result.(*core.Result)
		if r.IsVul {
			cmd.JsonEncoder.Encode(r)
			if cmd.JsonOutput != "" {
				cmd.JsonFile.Encode(r)
			}
			if cmd.DBOutput != "" {
				doc, err := bson.Marshal(r)
				hash := md5.Sum([]byte(r.Target + r.PocInfo.Info.Name))
				docid := hex.EncodeToString(hash[:])
				if err != nil {
					gologger.Error().Msgf("Could not Marshal resp: %s\n", err)
				} else {
					err = cmd.DB.Push(docid, doc)
				}
			}
		}
		lock.Unlock()
	}
	options.PocsFilePath = cmd.PocsFilePath

	cmd.JsonDecoder = json.NewDecoder(os.Stdin)
	cmd.JsonEncoder = json.NewEncoder(os.Stdout)
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)
	cmd.Pocs = cmd.GetAllPoc()
	ex_service := []string{"", " ", "http", "https"}
	if cmd.JsonOutput != "" {
		file, err := os.Create(cmd.JsonOutput)
		if err != nil {
			return errors.Wrap(err, "could not create json file")
		}
		defer file.Close()
		cmd.JsonFile = json.NewEncoder(file)
	}
	var err error
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

		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatal(err)
		}
		if cmd.PortInfo {
			cmd.JsonEncoder.Encode(ipResult)
		}
		for _, pc := range cmd.Pocs {
			pc := pc
			if cmd.Finger {
				var finger []string
				if !utl.Listcontains(ex_service, ipResult.Service) {
					finger = append(ipResult.Apps, ipResult.Service)
				} else {
					finger = ipResult.Apps
				}
				if !Filterfinger(finger, pc.Id, pc.Info.Name) {
					continue
				}
			}
			var target string
			if ipResult.URL != "" {
				target = ipResult.URL
			} else {
				target = ipResult.Host + ":" + strconv.Itoa(ipResult.Port)
			}
			cmd.ThreadManager.Wait()
			go func(target string, pc *poc.Poc) {
				log.Printf("running：%s-%s", target, pc.Info.Name)
				defer cmd.ThreadManager.Done()
				ck := core.Checker{
					Options:         options,
					OriginalRequest: &http.Request{},
					VariableMap:     make(map[string]any),
					Result:          &core.Result{},
					CustomLib:       core.NewCustomLib(),
					FastClient:      &http2.FastClient{},
				}
				if len(pc.Gopoc) > 0 {
					if err := ck.CheckGopoc(target, pc.Gopoc); err != nil {
						log.Println(err.Error())
					}
					return
				}
				if err := ck.Check(target, *pc); err != nil {
					log.Println(err.Error())
				}
			}(target, &pc)
		}

	}
	return nil
}

func (cmd *PocServiceCommand) GetAllPoc() []poc.Poc {
	// init pocs
	allPocsEmbedYamlSlice := []string{}
	if len(options.PocsFilePath) > 0 {
		options.PocsDirectory.Set(options.PocsFilePath)
	} else {
		// init default afrog-pocs
		if allDefaultPocsYamlSlice, err := pocs.GetPocs(); err == nil {
			allPocsEmbedYamlSlice = append(allPocsEmbedYamlSlice, allDefaultPocsYamlSlice...)
		}
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			options.PocsDirectory.Set(pocsDir)
		}
	}
	cl := catalog.New("")
	allPocsYamlSlice := cl.GetPocsPath(options.PocsDirectory)
	if len(allPocsYamlSlice) == 0 && len(allPocsEmbedYamlSlice) == 0 {
		return nil
	}

	var pocSlice []poc.Poc

	for _, pocYaml := range allPocsYamlSlice {
		p, err := poc.ReadPocs(pocYaml)
		if err != nil {
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	for _, pocEmbedYaml := range allPocsEmbedYamlSlice {
		p, err := pocs.ReadPocs(pocEmbedYaml)
		if err != nil {
			continue
		}
		pocSlice = append(pocSlice, p)
	}

	// added gopoc @date: 2022.6.19
	gopocNameSlice := gopoc.MapGoPocName()
	if len(gopocNameSlice) > 0 {
		for _, v := range gopocNameSlice {
			poc := poc.Poc{}
			poc.Gopoc = v
			poc.Id = v
			poc.Info.Name = v
			poc.Info.Severity = "unkown"
			pocSlice = append(pocSlice, poc)
		}
	}
	// added search poc by keywords
	newPocSlice := []poc.Poc{}
	if len(cmd.Search) > 0 && options.SetSearchKeyword() {
		for _, v := range pocSlice {
			if options.CheckPocKeywords(v.Id, v.Info.Name) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else if len(options.Severity) > 0 && options.SetSeverityKeyword() {
		// added severity filter @date: 2022.6.13 10:58
		for _, v := range pocSlice {
			if options.CheckPocSeverityKeywords(v.Info.Severity) {
				newPocSlice = append(newPocSlice, v)
			}
		}
	} else {
		newPocSlice = append(newPocSlice, pocSlice...)
	}

	return newPocSlice
}

func printPathLog(upgrade *upgrade.Upgrade) {
	fmt.Println("PATH:")
	fmt.Println("   " + options.Config.GetConfigPath())
	if options.UpdatePocs {
		fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.LastestVersion)
	} else {
		if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
			fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion + " (" + upgrade.LastestVersion + ")")
		} else {
			fmt.Println("   " + poc.GetPocPath() + " v" + upgrade.CurrVersion)
		}
	}
}

func Filterfinger(finger []string, pocid string, pocname string) bool {
	//elasticsearch
	if len(finger) > 0 {
		for _, v := range finger {
			v = strings.ToLower(v)
			if strings.Contains(strings.ToLower(pocid), v) || strings.Contains(strings.ToLower(pocname), v) {
				return true
			}
		}
	}
	return false
}
