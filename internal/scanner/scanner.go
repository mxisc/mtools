package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type IPVersion string

const (
	IPv4 IPVersion = "ipv4"
	IPv6 IPVersion = "ipv6"
)

type ScanOptions struct {
	Host      string
	StartPort int
	EndPort   int
	Workers   int
	Timeout   time.Duration
	IPVersion IPVersion
}

type OpenPort struct {
	Port     int
	Duration time.Duration
}

type Progress struct {
	CheckedPort  int
	CheckedCount int
	Total        int
	Open         *OpenPort
}

type workerResult struct {
	port     int
	openPort *OpenPort
}

func (o ScanOptions) Validate() error {
	if o.Host == "" {
		return errors.New("host 不能为空")
	}
	if o.StartPort < 1 || o.StartPort > 65535 {
		return errors.New("起始端口必须在 1-65535 之间")
	}
	if o.EndPort < 1 || o.EndPort > 65535 {
		return errors.New("结束端口必须在 1-65535 之间")
	}
	if o.StartPort > o.EndPort {
		return errors.New("起始端口不能大于结束端口")
	}
	if o.Workers < 1 {
		return errors.New("线程数必须大于 0")
	}
	if o.Timeout <= 0 {
		return errors.New("超时时间必须大于 0")
	}
	if o.IPVersion == "" {
		o.IPVersion = IPv4
	}
	if o.IPVersion != IPv4 && o.IPVersion != IPv6 {
		return errors.New("IP 版本必须为 ipv4 或 ipv6")
	}

	return nil
}

func Scan(ctx context.Context, opts ScanOptions, onProgress func(Progress)) ([]OpenPort, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	if _, err := net.LookupIP(opts.Host); err != nil {
		return nil, fmt.Errorf("主机解析失败: %w", err)
	}

	total := opts.EndPort - opts.StartPort + 1
	jobs := make(chan int)
	results := make(chan workerResult)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				results <- scanPort(opts.Host, port, opts.Timeout, opts.IPVersion)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for port := opts.StartPort; port <= opts.EndPort; port++ {
			select {
			case <-ctx.Done():
				return
			case jobs <- port:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	openPorts := make([]OpenPort, 0)
	checkedCount := 0

	for result := range results {
		checkedCount++
		if result.openPort != nil {
			openPorts = append(openPorts, *result.openPort)
		}

		if onProgress != nil {
			onProgress(Progress{
				CheckedPort:  result.port,
				CheckedCount: checkedCount,
				Total:        total,
				Open:         result.openPort,
			})
		}
	}

	if err := ctx.Err(); err != nil {
		sort.Slice(openPorts, func(i, j int) bool {
			return openPorts[i].Port < openPorts[j].Port
		})
		return openPorts, err
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts, nil
}

func scanPort(host string, port int, timeout time.Duration, ipVersion IPVersion) workerResult {
	var network string
	if ipVersion == IPv6 {
		network = "tcp6"
	} else {
		network = "tcp4"
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return workerResult{port: port}
	}
	defer conn.Close()

	return workerResult{
		port: port,
		openPort: &OpenPort{
			Port:     port,
			Duration: time.Since(start),
		},
	}
}
