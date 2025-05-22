package main

import (
	"fmt"

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
	out, _ := adbClient.Shell("ls /storage/emulated/0")
	fmt.Printf("%s", string(out))

	//out1, _ := adbClient.Ls("/storage/emulated/0")
	//fmt.Printf("%+v", out1)
	//fmt.Printf("eee")

	//adbClient.Pull("/storage/emulated/0/test990.pdf", "77779.pdf")

	//	pushErr := adbClient.Push("77779.pdf", "/storage/emulated/0/test9906611.pdf", 0644)
	//fmt.Printf("pushErr:%+v\r\n", pushErr)
	adbClient.Forward("tcp:6100", "localabstract:scrcpy")
	fmt.Scanln()
}
