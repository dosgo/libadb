package main

import (
	"fmt"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test"}

	// Scan intranet connections
	adbClient.Pair("030584", "192.168.171.147:33161")

	// Manual connection
	adbClient.Connect("192.168.171.147:46363")
	//Shell Commands
	//	out, _ := adbClient.Shell("ls /storage/emulated/0")
	//fmt.Printf("%s", string(out))

	//out1, _ := adbClient.Ls("/storage/emulated/0")
	//fmt.Printf("%+v", out1)
	//fmt.Printf("eee")

	//adbClient.Pull("/storage/emulated/0/test990.pdf", "77779.pdf")

	//	pushErr := adbClient.Push("77779.pdf", "/storage/emulated/0/test9906611.pdf", 0644)
	//fmt.Printf("pushErr:%+v\r\n", pushErr)

	pushErr := adbClient.Push("scrcpy-server-v3.2", "/data/local/tmp/scrcpy-server2", 0644)
	fmt.Printf("pushErr:%+v\r\n", pushErr)
	//var scid = "111rtr"
	adbClient.Reverse("localabstract:scrcpy", "tcp:6000")
	fmt.Printf("StartForward1\r\n")
	out, _ := adbClient.Shell("CLASSPATH=/data/local/tmp/scrcpy-server2 app_process / com.genymobile.scrcpy.Server 3.2")
	fmt.Printf("out:%+v\r\n", out)

	fmt.Scanln()
}
