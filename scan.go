package libadb

import (
	"context"
	"fmt"

	"github.com/grandcat/zeroconf"
)

var SERVICE_TYPE_ADB = "adb"
var SERVICE_TYPE_TLS_PAIRING = "adb-tls-pairing"
var SERVICE_TYPE_TLS_CONNECT = "adb-tls-connect"

func (adbClient *AdbClient) scanAddr(ctx context.Context, code int) error {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return err
	}
	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if code == 0 {
				adbClient.Connect(fmt.Sprintf("%s:%d", entry.AddrIPv4, entry.Port))
			} else {
				adbClient.Pair(fmt.Sprintf("%d", code), fmt.Sprintf("%s:%d", entry.AddrIPv4, entry.Port))
				fmt.Printf("pair addr:%s:%d\r\n", entry.AddrIPv4, entry.Port)
			}
		}
	}(entries)
	if code == 0 {
		resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_CONNECT), "local.", entries)
	} else {
		resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_PAIRING), "local.", entries)
	}
	return nil
}

func (adbClient *AdbClient) ScanConnect(ctx context.Context) error {
	adbClient.scanAddr(ctx, 0)
	return nil
}
func (adbClient *AdbClient) ScanPair(ctx context.Context, code int) error {
	adbClient.scanAddr(ctx, code)
	return nil
}
