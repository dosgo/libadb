package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {

	//init

	startTime := time.Now()
	cmdPull := exec.Command("adb", "pull", "/storage/emulated/0/Download/v9.4.2d_tl_google_demo_20250424_1332.apk", "test.apk")
	cmdPull.Stdout = os.Stdout
	cmdPull.Stderr = os.Stderr
	cmdPull.Start()

	cmdPull.Wait()
	duration := time.Since(startTime)

	fmt.Printf("duration: %v\n", duration)

	//fmt.Scanln()
}
