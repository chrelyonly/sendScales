package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
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
	conn, err := net.Dial("tcp", tcpAddress)
	if err != nil {
		return fmt.Errorf("无法连接到 TCP 服务器 %s: %v", tcpAddress, err)
	}

	// 更新全局连接变量
	mu.Lock()
	tcpConn = conn
	mu.Unlock()

	fmt.Println("成功连接到 TCP 服务器！")
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
	fmt.Printf("收到请求: %s, %s, %s, %s\n", name, code, data, response)
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

// 检查证书文件是否存在，如果不存在则生成新的证书
func checkAndGenerateCert(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		fmt.Println("证书文件不存在，生成新的证书...")
		return generateCert(certFile, keyFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		fmt.Println("密钥文件不存在，生成新的密钥...")
		return generateCert(certFile, keyFile)
	}
	return nil
}

// 生成自签名证书和密钥
func generateCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("无法生成私钥: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("无法生成序列号: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("无法生成证书: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("无法创建证书文件: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("无法创建密钥文件: %v", err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("无法编码私钥: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	fmt.Println("成功生成证书和密钥文件")
	return nil
}

func main() {
	// 先尝试读取配置文件
	config, err := readConfig()
	if err != nil {
		// 如果读取失败，则提示用户输入配置信息
		fmt.Println("读取配置文件失败，使用默认配置。")

		// 提示用户输入配置信息
		reader := bufio.NewReader(os.Stdin)

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

	// 检查并生成证书文件
	err = checkAndGenerateCert("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("生成证书失败: %v\n", err)
	}

	// 设置日志输出到文件，确保日志文件使用UTF-8编码
	logFile, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v\n", err)
	}
	defer logFile.Close()

	// 设置日志输出格式和时间戳
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Llongfile)

	// 打印 TCP 服务器的 IP 和端口
	fmt.Printf("已连接至秤地址: %s\n", config.TCPIP+":"+config.TCPPort)

	// 打印本机 IP 地址和端口
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println(err)
	}
	for _, address := range addrs {
		// 检查 ip 地址是否是回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				fmt.Println("本机 IP 地址: http://", ipnet.IP.String()+":"+config.WebPort+" https://"+ipnet.IP.String()+":"+config.WebPortTLS)
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
}
