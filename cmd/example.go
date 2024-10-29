package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dosgo/libadb"
)

func main() {

	//init
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test"}

	// Scan intranet connections
	/*
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		defer cancel()
		adbClient.ScanConnect(ctx)

		//scan pair  //adb pair
		adbClient.ScanPair(ctx, 586479)
	*/
	// Manual connection
	adbClient.Connect("172.30.16.133:44645")
	//Shell Commands
	out, _ := adbClient.Shell("ls /storage/emulated/0")
	fmt.Printf("%s", string(out))

	//pull
	adbClient.Pull("/storage/emulated/0/test990.pdf", "7777.pdf")

	//install
	adbClient.Install("test6.apk")

	//push
	pushErr := adbClient.Push("test6.pdf", "/storage/emulated/0/test990.pdf", 0644)
	fmt.Printf("pushErr:%+v\r\n", pushErr)

	//Screencap
	screencapImg, _ := adbClient.Screencap()
	libadb.SaveImageAsFile(screencapImg, "testttt.png")

	// adb list
	lists, _ := adbClient.Ls("/storage/emulated/0/Download")
	for _, value := range lists {
		log.Printf("file:%+v %s\r\n", value.Name, time.Unix(int64(value.Time), 0).Format("2006-01-02 15:04:05"))
	}

	fmt.Scanln()
}
