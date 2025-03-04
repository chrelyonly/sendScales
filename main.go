package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 定义一个全局的 TCP 连接变量
var tcpConn net.Conn
var mu sync.Mutex

// 配置信息结构体
type Config struct {
	TCPIP      string `json:"tcp_ip"`
	TCPPort    string `json:"tcp_port"`
	WebPort    string `json:"web_port"`
	WebPortTLS string `json:"web_port_tls"`
}

// 连接到指定的 TCP 服务器
func connectToTCP(ip string, port string) error {
	// 构造完整的 TCP 地址
	tcpAddress := fmt.Sprintf("%s:%s", ip, port)

	// 建立与 TCP 服务器的连接
	conn, err := net.DialTimeout("tcp", tcpAddress, 1000*time.Millisecond)
	if err != nil {
		return fmt.Errorf("无法连接到 TCP 服务器 %s: %v", tcpAddress, err)
	}

	// 更新全局连接变量
	mu.Lock()
	tcpConn = conn
	mu.Unlock()

	color.Green("成功连接到 TCP 服务器！")
	return nil
}

// 转发数据到已连接的 TCP 服务器，并等待响应
func forwardToTCP(data string) (string, error) {
	// 锁定 TCP 连接，防止并发访问时发生冲突
	mu.Lock()
	defer mu.Unlock()

	// 如果连接已关闭，则重新连接
	if tcpConn == nil {
		return "", fmt.Errorf("TCP 连接未建立")
	}

	// 发送数据到 TCP 服务器
	_, err := tcpConn.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("发送数据到 TCP 服务器失败: %v", err)
	}

	// 等待 TCP 服务器响应
	response := make([]byte, 1024) // 假设响应最大为 1024 字节
	n, err := tcpConn.Read(response)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("读取 TCP 响应失败: %v", err)
	}

	// 返回接收到的响应
	return string(response[:n]), nil
}

// 处理 HTTP GET 请求
func handler(w http.ResponseWriter, r *http.Request) {
	// 设置 CORS 相关头信息，允许跨域访问
	//w.Header().Set("Access-Control-Allow-Origin", "*")                            // 允许所有域名访问
	//w.Header().Set("Access-Control-Allow-Methods", "GET, POST")                   // 允许的请求方法
	//w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization") // 允许的请求头
	//
	//// 如果是 OPTIONS 请求，直接返回 200 OK
	//if r.Method == http.MethodOptions {
	//	w.WriteHeader(http.StatusOK)
	//	return
	//}
	// 获取 GET 请求中的参数
	data := r.URL.Query().Get("data")
	name := r.URL.Query().Get("name")
	code := r.URL.Query().Get("code")

	// 如果 data 参数为空，返回错误
	if data == "" {
		http.Error(w, "缺少 'data' 参数", http.StatusBadRequest)
		return
	}

	// 将数据转发到 TCP 服务器并等待响应
	response, err := forwardToTCP(data)
	if err != nil {
		http.Error(w, fmt.Sprintf("转发数据失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 将 TCP 服务器的响应返回给 Web 客户端
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("TCP 服务器响应: %s", response)))
	//打印到终端
	color.Green("收到请求: %s, %s, %s, %s\n", name, code, data, response)
}

// 读取配置文件
func readConfig() (*Config, error) {
	file, err := os.Open("config.json")
	if err != nil {
		return nil, fmt.Errorf("无法打开配置文件: %v", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("无法解析配置文件: %v", err)
	}

	return &config, nil
}

// 保存配置文件
func saveConfig(config *Config) error {
	file, err := os.Create("config.json")
	if err != nil {
		return fmt.Errorf("无法创建配置文件: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(config)
	if err != nil {
		return fmt.Errorf("无法写入配置文件: %v", err)
	}

	return nil
}

func main() {
	// 提示用户输入配置信息
	reader := bufio.NewReader(os.Stdin)
	currentTime := time.Now()
	color.Green("当前时间: " + currentTime.Format("2006-01-02 15:04:05"))
	color.Cyan("输入1手动填写配置")
	color.Cyan("输入2自动识别秤")
	// 获取输入的传秤方式
	var way string
	for {
		fmt.Print("请选择启动方式 (1 或 2): ")
		input, _ := reader.ReadString('\n')
		way = strings.TrimSpace(input) // 去除前后空格和换行符

		// 判断是否为空或者无效输入
		if way == "" {
			color.Red("未输入，默认选择 2")
			way = "2"
			break
		} else if way != "1" && way != "2" {
			color.Red("输入错误，请输入 1 或 2")
		} else {
			break
		}
	}
	way = strings.TrimSpace(way)
	if way == "1" {
		// 先尝试读取配置文件
		config, err := readConfig()
		if err != nil {
			// 如果读取失败，则提示用户输入配置信息
			color.Green("读取配置文件失败，使用默认配置。")

			// 获取 TCP 服务器的 IP 地址
			fmt.Print("请输入 TCP 服务器 IP 地址: ")
			ip, _ := reader.ReadString('\n')
			ip = strings.TrimSpace(ip)

			// 获取 TCP 服务器的端口号
			fmt.Print("请输入 TCP 服务器端口号: ")
			port, _ := reader.ReadString('\n')
			port = strings.TrimSpace(port)

			// 获取 Web 服务器端口
			fmt.Print("请输入 Web 服务器端口号: ")
			webPort, _ := reader.ReadString('\n')
			webPort = strings.TrimSpace(webPort)

			// 获取 Web 服务器 HTTPS 端口
			fmt.Print("请输入 Web 服务器 HTTPS 端口号: ")
			webPortTLS, _ := reader.ReadString('\n')
			webPortTLS = strings.TrimSpace(webPortTLS)

			// 保存配置信息
			config = &Config{TCPIP: ip, TCPPort: port, WebPort: webPort, WebPortTLS: webPortTLS}
			err = saveConfig(config)
			if err != nil {
				log.Fatalf("保存配置失败: %v\n", err)
			}
		}

		// 在此进行 TCP 连接
		err = connectToTCP(config.TCPIP, config.TCPPort)
		if err != nil {
			log.Fatalf("无法连接到 TCP 服务器: %v\n", err)
		}
		// 打印 TCP 服务器的 IP 和端口
		color.Green("已连接至秤地址: %s\n", config.TCPIP+":"+config.TCPPort)

		// 打印本机 IP 地址和端口
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			fmt.Println(err)
		}
		for _, address := range addrs {
			// 检查 ip 地址是否是回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					color.Green("本机 IP 地址: http://" + ipnet.IP.String() + ":" + config.WebPort + " https://" + ipnet.IP.String() + ":" + config.WebPortTLS)
				}
			}
		}

		// 设置 HTTP 路由和处理函数
		http.HandleFunc("/send", handler)
		//https.HandleFunc("/send", handler)
		// 启动 HTTP 和 HTTPS 服务器
		go func() {
			if err := http.ListenAndServe(":"+config.WebPort, nil); err != nil {
				log.Fatalf("HTTP 服务器启动失败: %v\n", err)
			}
		}()

		go func() {
			if err := http.ListenAndServeTLS(":"+config.WebPortTLS, "cert.pem", "key.pem", nil); err != nil {
				log.Fatalf("HTTPS 服务器启动失败: %v\n", err)
			}
		}()
		// 阻止程序退出
		select {}
	} else if way == "2" {
		ips, err := scanLocalIPs()
		if err != nil || len(ips) == 0 {
			log.Fatalf("无法扫描局域网 IP: %v", err)
		}
		color.Blue("扫描到的局域网 IP 网段:")
		// 打印去重后的网段
		i := 1
		for index := range ips {
			color.Green(strconv.Itoa(i) + "." + ips[index])
			i++
		}
		color.Blue("请选择秤所在的IP(在秤的左上角查询秤IP)网段（输入编号）: ")
		reader := bufio.NewReader(os.Stdin)

		var choice string
		for {
			input, err := reader.ReadString('\n')
			if err != nil {
				color.Red("读取输入失败，默认选择 1")
				choice = "1"
				break
			}

			choice = strings.TrimSpace(input) // 去除换行和空格
			if choice == "" {
				color.Red("未输入，默认选择 1")
				choice = "1"
				break
			}

			// 检查输入是否为有效的数字
			if _, err := strconv.Atoi(choice); err != nil {
				color.Red("输入错误，请输入有效的编号")
			} else {
				break
			}
		}
		choice = strings.TrimSpace(choice)
		index := 0
		fmt.Sscanf(choice, "%d", &index)
		if index < 1 || index > len(ips) {
			log.Fatal("无效的选择")
			return
		}

		selectedIP := ips[index-1]
		subnet := selectedIP[:strings.LastIndex(selectedIP, ".")+1] + "0"

		color.Green("已选择网段: %s/24，正在扫描...\n", subnet)

		// 扫描该网段下所有 IP 的 4001 端口
		availableIPs := scanDevicesInSubnet(subnet, "4001")

		if len(availableIPs) == 0 {
			color.RedString("未发现未找到秤")
			return
		}

		// 4. 显示可用设备
		color.HiGreen("找到以下可用设备：")
		for i, ip := range availableIPs {
			color.Red("%d. %s\n", i+1, ip)
		}
		fmt.Print("请选择设备 IP（输入编号）: ")
		choice, err = reader.ReadString('\n')
		if err != nil {
			color.Red("读取输入失败, 默认选择 1")
			choice = "1"
		}

		choice = strings.TrimSpace(choice)

		// 如果用户没有输入，默认选择 1
		if choice == "" {
			color.Yellow("未输入任何值，默认选择 1")
			choice = "1"
		}

		// 校验输入是否是数字
		index, convErr := strconv.Atoi(choice)
		if convErr != nil || index < 1 || index > len(ips) {
			color.Red("输入无效，请输入有效编号")
			return
		}

		selectedIP = ips[index-1]
		fmt.Printf("已选择 IP: %s\n", selectedIP)

		index = 0
		fmt.Sscanf(choice, "%d", &index)
		if index < 1 || index > len(availableIPs) {
			log.Fatal("无效的选择")
			return
		}
		selectedDeviceIP := availableIPs[index-1]
		color.Green("已选择设备 IP: %s\n", selectedDeviceIP)

		// 5. 连接到选定的设备
		err = connectToTCP(selectedDeviceIP, "4001")
		if err != nil {
			log.Fatalf("无法连接到秤: %v\n", err)
			return
		}
		// 打印 TCP 服务器的 IP 和端口
		color.Green("已连接至秤: %s\n", selectedDeviceIP+":4001")

		// 打印本机 IP 地址和端口
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			fmt.Println(err)
		}
		for _, address := range addrs {
			// 检查 ip 地址是否是回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					color.Green("本机 IP 地址: http://" + ipnet.IP.String() + ":14778" + " https://" + ipnet.IP.String() + ":14779")
					color.Green("请将该地址填写在门店后台的打印机的(i达小屋传秤软件.exe)的https+端口地址：)处,然后再传秤界面上选择(新*传秤按钮)" + " https://" + ipnet.IP.String() + ":14779/send")
				}
			}
		}
		color.Green("访问以上网址返回(404 page not found)或(缺少 'data' 参数)则表示配置成功")
		color.Green("提示不安全则需要安装证书")
		// 设置 HTTP 路由和处理函数
		http.HandleFunc("/send", handler)
		//https.HandleFunc("/send", handler)
		// 启动 HTTP 和 HTTPS 服务器
		go func() {
			if err := http.ListenAndServe(":14778", nil); err != nil {
				log.Fatalf("HTTP 服务器启动失败: %v\n", err)
			}
		}()

		go func() {
			if err := http.ListenAndServeTLS(":14779", "cert.pem", "key.pem", nil); err != nil {
				log.Fatalf("HTTPS 服务器启动失败: %v\n", err)
			}
		}()
		// 阻止程序退出
		select {}
	} else {
		color.RedString("输入错误")
	}

}
func scanLocalIPs() ([]string, error) {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips, nil
}

// 扫描网段内开放 4001 端口的设备
func scanDevicesInSubnet(subnet string, port string) []string {
	subnetIPs := generateSubnetIPs(subnet) // 生成该网段所有 IP
	var availableIPs []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 50) // 限制并发数，避免网络阻塞

	color.Green("开始扫描网段 %s 端口 %s ...\n", subnet, port)

	for _, ip := range subnetIPs {
		wg.Add(1)
		semaphore <- struct{}{} // 控制并发

		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放并发控制

			address := fmt.Sprintf("%s:%s", ip, port)
			//color.Green()("正在扫描: %s\n", address) // 打印扫描进度

			conn, err := net.DialTimeout("tcp", address, 1000*time.Millisecond) // 设置超时
			if err == nil {
				mu.Lock()
				availableIPs = append(availableIPs, ip)
				mu.Unlock()
				color.Green("发现可用设备: %s\n", ip) // 发现可用 IP 时打印
				conn.Close()
			}
		}(ip)
	}

	wg.Wait()
	color.Green("扫描完成。")
	return availableIPs
}

// 生成 IP 网段（假设网段为 192.168.1.0/24）
func generateSubnetIPs(subnet string) []string {
	var subnetIPs []string
	baseIP := subnet[:strings.LastIndex(subnet, ".")+1] // 提取网段前缀，如 192.168.1.
	for i := 1; i < 255; i++ {                          // 遍历 1~254 号 IP
		subnetIPs = append(subnetIPs, fmt.Sprintf("%s%d", baseIP, i))
	}
	return subnetIPs
}
