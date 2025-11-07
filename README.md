###  RDP SSL 证书配置工具

> 一个图形化的 Windows RDP SSL 证书配置器。  
> 自动识别 ZIP 证书包中的证书与私钥，生成 `.pfx` 并导入系统证书存储区，设置远程桌面服务使用新证书。
> 25.11.07更新，选择好你的zip证书包后会在log区自动提示证书是正常的还是缺了文件
---

## ✨ 功能特性

- 🔍 自动识别 ZIP 包中的证书与私钥文件（支持 `.pem`, `.crt`, `.cer`, `.key` 等格式）
- 🧠 智能判断最合适的证书/私钥组合
- 🔒 一键生成 `.pfx` 文件（无需 OpenSSL），并导入到本机
- ⚙️ 设置 NETWORK SERVICE 私钥访问权限
- 🧾 自动写入 RDP 注册表项 `SSLCertificateSHA1Hash`
- 🔁 自动重启远程桌面服务（TermService，会让你当前的远程桌面断开）
- 💚 全程离线、无网络访问，安全可靠

---

## 📦 安装与运行

### 1️⃣ 安装依赖
只需一个外部库：
pip install cryptography

### 2️⃣ 运行程序
python rdp_ssl_tool.py

⚠️ 请右键 → 以管理员身份运行 CMD 或 PowerShell！
因为程序需要写入注册表和导入系统证书。

### 3️⃣注册表写入说明
| 项目 | 注册表路径                                                                                |
| --- | ----------------------------------------------------------------------------------------- |
| 位置 | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` |
| 键值 | `SSLCertificateSHA1Hash`                                                                  |
| 类型 | `REG_BINARY`                                                                              |
| 内容 | 证书 SHA1 指纹                                                                             |
