package main

import (
	"fmt"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test8"}
	//adbClient.Pair("246662", "192.168.78.123:37261")
	// Manual connection
	adbClient.Connect("192.168.67.69:5555")
	out, _ := adbClient.Shell("pm list packages")
	fmt.Printf("11%+s", out)
	//fmt.Scanln()
}
