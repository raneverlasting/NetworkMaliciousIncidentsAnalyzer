# Network Malicious Incidents Analyzer

Network Malicious Incidents Analyzer 是一个基于 Flask 构建的网络流量分析工具，旨在帮助用户检测和分析网络中的恶意行为。项目支持 Docker 部署，提供高效的流量分析能力和简洁的操作流程。

---

## 功能特点

- **实时流量分析**：基于流量日志检测潜在的恶意行为。
- **多种文件处理**：支持 Web、FTP、邮件等多种协议文件的分析。
- **GeoIP 集成**：提供地理位置信息分析。
- **Docker 化部署**：快速部署，方便管理。
- **高性能运行**：使用 Gunicorn 提供生产环境支持。

---

## 环境依赖

本项目支持通过 Docker 快速部署，运行环境要求如下：

- **操作系统**：推荐 Ubuntu 20.04 或以上版本
- **Docker**：需要预先安装 Docker 和 Docker Compose

如果未安装 Docker，可以使用以下命令进行安装：

### 安装 Docker
```bash
sudo apt update
sudo apt install docker.io -y
sudo systemctl start docker
sudo systemctl enable docker
```

### 重启 Docker
```bash
sudo systemctl restart docker
```

### 构建 Docker 镜像
```bash
sudo docker build -t my_flask_app .
```

### 运行 Docker 容器
```bash
sudo docker run -p 8000:8000 my_flask_app
```
