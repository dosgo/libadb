package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test8"}
	//adbClient.Pair("188423", "192.168.78.123:44767")
	// Manual connection
	adbClient.Connect("192.168.78.115:40753")
	out, _ := adbClient.Shell("pm list packages")
	fmt.Printf("11%+s", out)

	lists, _ := adbClient.Ls("/storage/emulated/0/Download")
	for _, value := range lists {
		log.Printf("file:%+v %s\r\n", value.Name, time.Unix(int64(value.Time), 0).Format("2006-01-02 15:04:05"))
	}
	err := adbClient.Pull("/storage/emulated/0/Download/中国国家铁路集团有限公司2022年年度报告.pdf", "test.pdf")
	fmt.Printf("pull err:%+v", err)
	//fmt.Scanln()
}
