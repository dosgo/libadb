package main

import (
	"fmt"
	"time"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test"}

	// Scan intranet connections
	//	adbClient.Pair("427100", "172.30.16.134:38393")

	// Manual connection
	adbClient.Connect("172.30.16.134:39379")
	//Shell Commands
	//	out, _ := adbClient.Shell("ls /storage/emulated/0")
	//fmt.Printf("%s", string(out))

	//out1, _ := adbClient.Ls("/storage/emulated/0")
	//fmt.Printf("%+v", out1)
	//fmt.Printf("eee")

	//adbClient.Pull("/storage/emulated/0/test990.pdf", "77779.pdf")

	//	pushErr := adbClient.Push("77779.pdf", "/storage/emulated/0/test9906611.pdf", 0644)
	//fmt.Printf("pushErr:%+v\r\n", pushErr)

	pushErr := adbClient.Push("scrcpy-server-v3.2", "/data/local/tmp/scrcpy-server1", 0644)
	fmt.Printf("pushErr:%+v\r\n", pushErr)
	var scid = "111"
	adbClient.Reverse("localabstract:scrcpy_"+scid, "tcp:6000")
	time.Sleep(time.Second * 10)
	fmt.Printf("StartForward1\r\n")
	out, _ := adbClient.Shell("CLASSPATH=/data/local/tmp/scrcpy-server1 app_process / com.genymobile.scrcpy.Server 3.2 log_level=info  scid=" + scid + "    &")
	fmt.Printf("out:%+v\r\n", out)

	fmt.Scanln()
}
