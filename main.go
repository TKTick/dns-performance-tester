package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// 配置文件结构体
type Config struct {
	Domains       []string      `yaml:"domains"`
	DNSServers    []string      `yaml:"dns_servers"`
	TestCount     int           `yaml:"test_count"`
	QueryInterval time.Duration `yaml:"query_interval"`
	Concurrency   int           `yaml:"concurrency"` // 新增并发数字段
	LogToFile     bool          `yaml:"log_to_file"` // 控制是否将日志写入文件
	SaveCsv       bool          `yaml:"save_csv"`    // 控制是否保存CSV文件
	TestRounds    int           `yaml:"test_rounds"` // 新增多轮测试字段

}

// DNS测试结果结构体
type DnsTestResult struct {
	Domain    string
	Server    string
	Timestamp time.Time
	Latency   time.Duration
}

// 定义DnsWorkItem结构体用于并发处理
type DnsWorkItem struct {
	Domain    string
	DNSServer string
}

type DnsTestContext struct {
	Config         *Config
	CSVFile        *os.File
	CSVWriter      *csv.Writer
	LogFile        *os.File
	Logger         *log.Logger
	TestRoundMutex sync.Mutex // 用于同步多轮测试的日志输出
}

// loadConfig 加载配置文件
func loadConfig(filename string) (*Config, error) {
	var config Config
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开配置文件: %w", err)
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	return &config, nil
}

// setupLogging 设置日志
func setupLogging(logFile string) (*os.File, error) {
	logf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开日志文件失败: %w", err)
	}
	return logf, nil
}

// initCSV 初始化CSV
func (dt *DnsTestContext) initCSV(filename string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("创建/打开CSV文件失败: %w", err)
	}
	dt.CSVFile = file

	dt.CSVWriter = csv.NewWriter(file)
	defer dt.CSVWriter.Flush() // 这里保持不变，但在程序结束前也应确保Flush()

	header := []string{"域名", "DNS服务器", "时间戳", "延时(毫秒)"}
	if err := dt.CSVWriter.Write(header); err != nil {
		return fmt.Errorf("写入CSV表头失败: %w", err)
	}

	return nil
}

// writeResultToCsv 将结果保存到CSV
func writeResultToCsv(dt *DnsTestContext, result DnsTestResult) error {
	record := []string{
		result.Domain,
		result.Server,
		result.Timestamp.Format(time.RFC3339),
		strconv.FormatFloat(result.Latency.Seconds()*1000, 'f', -1, 64),
	}

	if err := dt.CSVWriter.Write(record); err != nil {
		return fmt.Errorf("写入CSV记录失败: %w", err)
	}
	return nil
}

// 初始化DnsTestContext 根据配置文件初始化log和csv
func NewDnsTestContext(config *Config) (*DnsTestContext, error) {
	dt := &DnsTestContext{
		Config: config,
	}
	if config.SaveCsv {
		filename := fmt.Sprintf("./dns_test_results/dns_test_%s.csv", time.Now().Format("2006-01-02_15-04-05"))
		err := dt.initCSV(filename)
		if err != nil {
			return nil, err
		}
	}
	if config.LogToFile {
		logf, err := setupLogging("dns_test.log")
		if err != nil {
			return nil, err
		}
		dt.LogFile = logf
		multiWriter := io.MultiWriter(os.Stdout, dt.LogFile)
		dt.Logger = log.New(multiWriter, "", log.LstdFlags|log.Lmicroseconds)
	} else {
		dt.Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	}
	return dt, nil
}

// StartAndRecordLatencies 执行指定次数的DNS查询并记录延迟结果。
func StartAndRecordLatencies(domain, dnsServer string, count int, interval time.Duration, logger *log.Logger) (avgDelay time.Duration, delays []time.Duration, err error) {
	delays = make([]time.Duration, 0, count)
	for i := 1; i <= count; i++ {
		_, latency, err := PerformDNSLookup(domain, dnsServer) // 丢弃响应信息，仅保留延时
		if err != nil {
			logger.Printf("域名: %s DNS: %s 第 %-2v 次 查询错误: %v\n", domain, dnsServer, i, err)
			continue
		}
		delays = append(delays, latency)
		logger.Printf("域名: %s DNS: %s 第 %-2v 次 延时: %v\n", domain, dnsServer, i, latency)
		time.Sleep(interval)
	}

	// 计算平均延时
	avgDelay = calculateAverageDelay(delays)
	return avgDelay, delays, nil
}

// PerformDNSLookup 直接使用Go库实现DNS查询，返回响应消息和查询耗时。
func PerformDNSLookup(domain, dnsServer string) (*dns.Msg, time.Duration, error) {
	opts := &upstream.Options{
		Timeout:            5 * time.Second, // 超时时间设置为 5S
		InsecureSkipVerify: false,
		HTTPVersions:       []upstream.HTTPVersion{upstream.HTTPVersion11},
	} // 根据实际需求调整上游选项

	startTime := time.Now()

	u, err := upstream.AddressToUpstream(dnsServer, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("创建上游服务失败: %w", err)
	}

	req := &dns.Msg{}
	// 设置请求参数（例如：域名、类型等）
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: domain + ".", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	reply, err := u.Exchange(req)
	if err != nil {
		return nil, 0, fmt.Errorf("执行DNS查询失败: %w", err)
	}

	elapsed := time.Since(startTime)

	return reply, elapsed, nil
}

// calculateAverageDelay 计算延迟数组的平均值。
func calculateAverageDelay(delays []time.Duration) time.Duration {
	var sum time.Duration
	for _, delay := range delays {
		sum += delay
	}
	return sum / time.Duration(len(delays))
}

// performTestRound 函数处理一轮测试
func performTestRound(dt *DnsTestContext, round int) error {
	workQueue := make(chan DnsWorkItem, len(dt.Config.Domains)*len(dt.Config.DNSServers))
	var wg sync.WaitGroup
	wg.Add(dt.Config.Concurrency)
	for i := 0; i < dt.Config.Concurrency; i++ {
		go func() {
			defer wg.Done()

			for work := range workQueue {
				avgDelay, delays, err := StartAndRecordLatencies(work.Domain, work.DNSServer, dt.Config.TestCount, dt.Config.QueryInterval, dt.Logger)
				if err != nil {
					dt.Logger.Printf("处理域名: %s 和 DNS: %s 时出错: %v\n", work.Domain, work.DNSServer, err)
					continue
				}

				dt.Logger.Printf("域名: %s DNS: %s 平均延时: %.2fms\n", work.Domain, work.DNSServer, avgDelay.Seconds()*1000)

				if dt.Config.SaveCsv {
					for _, delay := range delays {
						result := DnsTestResult{
							Domain:    work.Domain,
							Server:    work.DNSServer,
							Timestamp: time.Now(),
							Latency:   delay,
						}
						if err := writeResultToCsv(dt, result); err != nil {
							dt.Logger.Printf("将测试结果写入CSV文件失败: %v\n", err)
						}
					}
				}
			}
		}()
	}

	for _, domain := range dt.Config.Domains {
		for _, dnsServer := range dt.Config.DNSServers {
			workQueue <- DnsWorkItem{Domain: domain, DNSServer: dnsServer}
		}
	}
	close(workQueue) // 关闭工作队列

	wg.Wait() // 等待所有goroutine完成任务

	dt.TestRoundMutex.Lock()
	dt.Logger.Printf("第 %d 轮测试完成。\n", round)
	dt.TestRoundMutex.Unlock()

	return nil
}

func main() {
	configFile := "config.yaml"
	cfg, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	for round := 1; round <= cfg.TestRounds; round++ {
		dt, err := NewDnsTestContext(cfg)
		if err != nil {
			log.Fatalf("初始化应用程序上下文失败: %v", err)
		}
		defer dt.CSVFile.Close()
		defer dt.LogFile.Close()
		if err := performTestRound(dt, round); err != nil {
			dt.Logger.Printf("执行第 %d 轮测试时出错: %v\n", round, err)
		}
		// 在程序结束前强制刷新缓存中的数据到CSV文件（如果启用）
		if dt.Config.SaveCsv {
			dt.CSVWriter.Flush()
		}
	}
}
