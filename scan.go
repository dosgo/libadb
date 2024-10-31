package libadb

import (
	"context"
	"errors"
	"fmt"

	"github.com/grandcat/zeroconf"
)

var SERVICE_TYPE_ADB = "adb"
var SERVICE_TYPE_TLS_PAIRING = "adb-tls-pairing"
var SERVICE_TYPE_TLS_CONNECT = "adb-tls-connect"

func scanAddr(ctx context.Context, action int) ([]string, error) {
	resolver, err := zeroconf.NewResolver(nil)
	var addrs []string
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			if action == 1 {
				addrs = append(addrs, fmt.Sprintf("%s:%d", entry.AddrIPv4, entry.Port))
			} else {
				fmt.Printf("pair addr:%s:%d\r\n", entry.AddrIPv4, entry.Port)
				addrs = append(addrs, fmt.Sprintf("%s:%d", entry.AddrIPv4, entry.Port))
			}
		}
	}(entries)
	if action == 0 {
		resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_CONNECT), "local.", entries)
	} else {
		resolver.Browse(ctx, fmt.Sprintf("_%s._tcp", SERVICE_TYPE_TLS_PAIRING), "local.", entries)
	}
	return addrs, nil
}

func (adbClient *AdbClient) ScanConnect(ctx context.Context) error {
	addrs, err := scanAddr(ctx, 1)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("not find addr")
	}
	return adbClient.Connect(addrs[0])
}
func (adbClient *AdbClient) ScanPair(ctx context.Context, code int) error {
	addrs, err := scanAddr(ctx, 2)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("not find addr")
	}
	return adbClient.Pair(fmt.Sprintf("%d", code), addrs[0])
}

func ScanAddrs(ctx context.Context, action int) ([]string, error) {
	return scanAddr(ctx, action)
}
