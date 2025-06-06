package main

import (
	"fmt"
	"time"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test8"}
	adbClient.Pair("356447", "172.30.17.78:37395")
	// Manual connection
	adbClient.Connect("172.30.17.78:42201")
	startTime := time.Now()
	err := adbClient.Pull("/storage/emulated/0/Download/v9.4.2d_tl_google_demo_20250424_1332.apk", "test.apk")
	fmt.Printf("pull err:%+v", err)
	duration := time.Since(startTime)

	fmt.Printf("duration: %v\n", duration)

	//fmt.Scanln()
}
