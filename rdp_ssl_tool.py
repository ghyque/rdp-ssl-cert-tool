# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import winreg
import os
import ctypes
import threading
import zipfile
import tempfile
import shutil
import re
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
import hashlib


class RDPCertificateGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RDP SSL 证书配置工具")
        self.root.geometry("600x600")
        self.root.resizable(False, False)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.temp_dir = None
        self.is_running = False

        self.center_window()
        self.create_widgets()
        self.create_log_area()

    def on_closing(self):
        if self.is_running:
            if not messagebox.askokcancel("退出", "配置正在运行，确定要退出吗？"):
                return
        self.root.destroy()

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'+{x}+{y}')

    def create_widgets(self):
        font_main = ("微软雅黑", 10)
        font_small = ("微软雅黑", 9)

        main_frame = ttk.Frame(self.root, padding="12")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(main_frame, text="RDP SSL 证书配置工具", font=("微软雅黑", 18, "bold"))
        title_label.pack(pady=(0, 8))

        # ZIP 文件选择
        file_frame = ttk.LabelFrame(main_frame, text="1. 选择证书 ZIP 文件", padding="6")
        file_frame.pack(fill=tk.X, pady=(0, 6))
        file_selection_frame = ttk.Frame(file_frame)
        file_selection_frame.pack(fill=tk.X)
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_selection_frame, textvariable=self.file_path_var,
                                   state='readonly', font=font_main)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        self.browse_button = ttk.Button(file_selection_frame, text="浏览", command=self.browse_file)
        self.browse_button.pack(side=tk.RIGHT)

        # 密码输入
        password_frame = ttk.LabelFrame(main_frame, text="2. PFX 文件密码（可选）", padding="6")
        password_frame.pack(fill=tk.X, pady=(0, 6))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", font=font_main)
        self.password_entry.pack(fill=tk.X)
        password_options_frame = ttk.Frame(password_frame)
        password_options_frame.pack(fill=tk.X, pady=(4, 0))
        self.no_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_options_frame, text="PFX 无密码",
                        variable=self.no_password_var,
                        command=self.toggle_password_entry).pack(side=tk.LEFT)
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(password_options_frame, text="显示密码",
                        variable=self.show_password_var,
                        command=self.toggle_show_password).pack(side=tk.RIGHT)

        # 导入选项
        import_frame = ttk.LabelFrame(main_frame, text="3. 证书导入选项", padding="6")
        import_frame.pack(fill=tk.X, pady=(0, 6))
        self.import_cert_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(import_frame, text="导入证书到 Windows 证书存储（本地计算机 -> 个人）",
                        variable=self.import_cert_var).pack(anchor=tk.W)
        self.set_private_key_permission_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(import_frame, text="设置 NETWORK SERVICE 私钥读取权限",
                        variable=self.set_private_key_permission_var).pack(anchor=tk.W, pady=(2, 0))

        # 按钮区域
        button_frame = ttk.Frame(main_frame, height=50)
        button_frame.pack(fill=tk.X, pady=(8, 6))
        button_frame.pack_propagate(False)
        inner_button_frame = ttk.Frame(button_frame)
        inner_button_frame.place(relx=0.5, rely=0.5, anchor="center")
        button_width = 14
        ttk.Button(inner_button_frame, text="配置 RDP 证书",
                   command=self.start_configuration, width=button_width).pack(side=tk.LEFT, padx=4)
        ttk.Button(inner_button_frame, text="验证配置",
                   command=self.verify_configuration, width=button_width).pack(side=tk.LEFT, padx=4)
        ttk.Button(inner_button_frame, text="清空日志",
                   command=self.clear_log, width=button_width).pack(side=tk.LEFT, padx=4)

    def create_log_area(self):
        log_frame = ttk.LabelFrame(self.root, text="操作日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD, font=("微软雅黑", 9))
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # ==== 功能逻辑 ====
    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def browse_file(self):
        f = filedialog.askopenfilename(title="选择证书 ZIP 文件", filetypes=[("ZIP 文件", "*.zip"), ("所有文件", "*.*")])
        if f:
            self.file_path_var.set(f)
            self.log(f"选择证书 ZIP 文件: {f}")

    def toggle_password_entry(self):
        if self.no_password_var.get():
            self.password_entry.config(state='disabled')
            self.password_var.set("")
        else:
            self.password_entry.config(state='normal')

    def toggle_show_password(self):
        self.password_entry.config(show="" if self.show_password_var.get() else "*")

    def start_configuration(self):
        if not self.check_admin():
            return
        zip_path = self.file_path_var.get()
        if not zip_path or not os.path.exists(zip_path):
            messagebox.showerror("错误", "请选择有效的 ZIP 文件！")
            return
        password = None if self.no_password_var.get() else self.password_var.get()
        self.is_running = True
        threading.Thread(target=self.configure_certificate, args=(zip_path, password), daemon=True).start()

    def check_admin(self):
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showerror("权限错误", "请以管理员身份运行此程序！")
                return False
            return True
        except:
            messagebox.showerror("权限错误", "无法检查管理员权限！")
            return False

    def identify_certificate_files(self, directory):
        """智能识别证书和私钥文件"""
        cert_files = []
        key_files = []
        
        # 证书文件扩展名模式
        cert_patterns = [
            r'.*\.(cer|crt|pem)$',  # 常见证书扩展名
            r'.*cert.*',            # 包含cert
            r'.*chain.*',           # 包含chain
            r'.*fullchain.*',       # 包含fullchain
            r'^[a-f0-9]{8}\.cer$',  # 类似哈希值的文件名
        ]
        
        # 私钥文件扩展名模式
        key_patterns = [
            r'.*\.key$',            # 常见私钥扩展名
            r'.*priv.*',            # 包含priv
            r'.*private.*',         # 包含private
        ]
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if not os.path.isfile(filepath):
                continue
                
            lower_filename = filename.lower()
            
            # 检查是否为证书文件
            for pattern in cert_patterns:
                if re.match(pattern, lower_filename):
                    # 验证文件内容确实是证书
                    if self.is_valid_certificate(filepath):
                        cert_files.append((filename, filepath))
                        self.log(f"识别为证书文件: {filename}")
                    break
            
            # 检查是否为私钥文件
            for pattern in key_patterns:
                if re.match(pattern, lower_filename):
                    # 验证文件内容确实是私钥
                    if self.is_valid_private_key(filepath):
                        key_files.append((filename, filepath))
                        self.log(f"识别为私钥文件: {filename}")
                    break
        
        return cert_files, key_files

    def is_valid_certificate(self, filepath):
        """验证文件是否为有效的证书"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # 尝试解析为 PEM 格式证书
            try:
                certificate = x509.load_pem_x509_certificate(content, default_backend())
                return True
            except:
                pass
            
            # 尝试解析为 DER 格式证书
            try:
                certificate = x509.load_der_x509_certificate(content, default_backend())
                return True
            except:
                pass
            
            # 检查文件内容是否包含证书特征
            text_content = content.decode('utf-8', errors='ignore')
            if '-----BEGIN CERTIFICATE-----' in text_content:
                return True
                
        except Exception:
            pass
            
        return False

    def is_valid_private_key(self, filepath):
        """验证文件是否为有效的私钥"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # 尝试解析为 PEM 格式私钥
            try:
                private_key = serialization.load_pem_private_key(content, password=None, backend=default_backend())
                return True
            except:
                pass
            
            # 检查文件内容是否包含私钥特征
            text_content = content.decode('utf-8', errors='ignore')
            if any(marker in text_content for marker in [
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----BEGIN PRIVATE KEY-----',
                '-----BEGIN EC PRIVATE KEY-----'
            ]):
                return True
                
        except Exception:
            pass
            
        return False

    def extract_zip_and_create_pfx(self, zip_path, pfx_password):
        try:
            self.log("开始解压 ZIP 文件...")
            self.temp_dir = tempfile.mkdtemp()
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(self.temp_dir)
            
            # 智能识别证书和私钥文件
            self.log("正在智能识别证书文件...")
            cert_files, key_files = self.identify_certificate_files(self.temp_dir)
            
            if not cert_files:
                raise Exception("未找到有效的证书文件")
            if not key_files:
                raise Exception("未找到有效的私钥文件")
            
            # 选择最可能的证书和私钥文件
            cert_file = self.select_best_candidate(cert_files, is_cert=True)
            key_file = self.select_best_candidate(key_files, is_cert=False)
            
            self.log(f"使用证书文件: {cert_file[0]}")
            self.log(f"使用私钥文件: {key_file[0]}")
            
            # 使用 cryptography 库读取证书和私钥
            self.log("使用 Python cryptography 库处理证书...")
            
            # 读取证书
            certificate = self.load_certificate(cert_file[1])
            if not certificate:
                raise Exception(f"无法读取证书文件: {cert_file[0]}")
            
            # 读取私钥
            private_key = self.load_private_key(key_file[1])
            if not private_key:
                raise Exception(f"无法读取私钥文件: {key_file[0]}")
            
            # 创建 PFX 文件
            pfx_path = os.path.join(os.path.dirname(zip_path), "hyque.pfx")
            pfx_password_bytes = pfx_password.encode('utf-8') if pfx_password else None
            
            pfx_data = pkcs12.serialize_key_and_certificates(
                name=b"hyque",
                key=private_key,
                cert=certificate,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(pfx_password_bytes) if pfx_password_bytes 
                else serialization.NoEncryption()
            )
            
            with open(pfx_path, 'wb') as f:
                f.write(pfx_data)
                
            self.log(f"✅ 生成 PFX 文件成功: {pfx_path}")
            return pfx_path
            
        except Exception as e:
            self.log(f"❌ PFX 生成失败: {e}")
            # 显示找到的文件列表以便调试
            if 'cert_files' in locals():
                self.log(f"找到的证书文件: {[f[0] for f in cert_files]}")
            if 'key_files' in locals():
                self.log(f"找到的私钥文件: {[f[0] for f in key_files]}")
            return None

    def load_certificate(self, filepath):
        """加载证书文件，支持 PEM 和 DER 格式"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # 尝试 PEM 格式
            try:
                return x509.load_pem_x509_certificate(content, default_backend())
            except:
                pass
            
            # 尝试 DER 格式
            try:
                return x509.load_der_x509_certificate(content, default_backend())
            except:
                pass
                
        except Exception as e:
            self.log(f"证书加载错误: {e}")
            
        return None

    def load_private_key(self, filepath):
        """加载私钥文件"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # 尝试加载 PEM 私钥
            try:
                return serialization.load_pem_private_key(content, password=None, backend=default_backend())
            except:
                pass
                
        except Exception as e:
            self.log(f"私钥加载错误: {e}")
            
        return None

    def select_best_candidate(self, files, is_cert=True):
        """选择最合适的证书或私钥文件"""
        if not files:
            return None
            
        if len(files) == 1:
            return files[0]
        
        # 根据文件名特征排序优先级
        def get_priority(filename):
            lower_name = filename.lower()
            priority = 0
            
            if is_cert:
                # 证书文件优先级
                if 'fullchain' in lower_name: priority += 30
                if 'chain' in lower_name: priority += 20
                if 'cert' in lower_name: priority += 10
                if lower_name.endswith('.cer'): priority += 5
                if lower_name.endswith('.crt'): priority += 4
            else:
                # 私钥文件优先级
                if 'privkey' in lower_name: priority += 30
                if 'private' in lower_name: priority += 20
                if 'key' in lower_name: priority += 10
                if lower_name.endswith('.key'): priority += 5
            
            return priority
        
        # 按优先级排序
        sorted_files = sorted(files, key=lambda x: get_priority(x[0]), reverse=True)
        return sorted_files[0]

    def get_thumbprint(self, pfx_path, password):
        try:
            # 使用 cryptography 库读取 PFX 并计算指纹
            with open(pfx_path, 'rb') as f:
                pfx_data = f.read()
            
            password_bytes = password.encode('utf-8') if password else None
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data, password_bytes, default_backend()
            )
            
            if certificate is None:
                raise Exception("无法从 PFX 文件中读取证书")
            
            # 计算 SHA1 指纹
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            sha1_hash = hashlib.sha1(cert_der).hexdigest().upper()
            thumbprint = ':'.join([sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2)])
            
            self.log(f"✅ 获取指纹成功: {thumbprint}")
            return thumbprint
        except Exception as e:
            self.log(f"❌ 获取指纹失败: {e}")
            return None

    def import_certificate_to_store(self, pfx, password):
        try:
            cmd = ["certutil", "-f", "-importpfx", pfx, "NoRoot"]
            if password: cmd[2:2] = ["-p", password]
            r = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if "成功" in r.stdout or "imported" in r.stdout:
                self.log("✅ 证书导入成功")
                return True
            self.log(r.stdout)
        except Exception as e:
            self.log(f"❌ 证书导入失败: {e}")
        return False

    def set_private_key_permissions(self, thumbprint):
        try:
            ps = f'''
            $cert = Get-ChildItem Cert:\\LocalMachine\\My | Where {{$_.Thumbprint -eq "{thumbprint.replace(':','')}" }}
            if ($cert) {{
                icacls "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys" /grant "NETWORK SERVICE:(R)" /T
                icacls "C:\\ProgramData\\Microsoft\\Crypto\\Keys" /grant "NETWORK SERVICE:(R)" /T
            }}
            '''
            subprocess.run(["powershell", "-Command", ps], capture_output=True, text=True, check=True)
            self.log("✅ 私钥权限设置完成")
        except Exception as e:
            self.log(f"❌ 权限设置失败: {e}")

    def configure_certificate(self, zip_path, password):
        try:
            self.log("开始配置 RDP SSL 证书...")
            pfx = self.extract_zip_and_create_pfx(zip_path, password)
            if not pfx: return
            thumb = self.get_thumbprint(pfx, password)
            if not thumb: return
            if self.import_cert_var.get():
                ok = self.import_certificate_to_store(pfx, password)
                if ok and self.set_private_key_permission_var.get():
                    self.set_private_key_permissions(thumb)
            # 写注册表
            data = bytes.fromhex(thumb.replace(':', ''))
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", 0, winreg.KEY_WRITE) as k:
                winreg.SetValueEx(k, "SSLCertificateSHA1Hash", 0, winreg.REG_BINARY, data)
            self.log("✅ 注册表写入完成")
            self.restart_service()
            messagebox.showinfo("成功", "RDP SSL 证书配置成功！")
        except Exception as e:
            self.log(f"❌ 配置失败: {e}")
            messagebox.showerror("错误", str(e))
        finally:
            self.is_running = False
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)

    def restart_service(self):
        ps = '''
        Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Service -Name "TermService" -ErrorAction Stop
        '''
        try:
            subprocess.run(["powershell", "-Command", ps], capture_output=True, text=True, check=True, timeout=30)
            self.log("✅ 终端服务已重启")
        except Exception as e:
            self.log(f"⚠️ 重启服务失败: {e}")

    def verify_configuration(self):
        if not self.check_admin():
            return
        try:
            key = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ) as k:
                val, _ = winreg.QueryValueEx(k, "SSLCertificateSHA1Hash")
            tp = ''.join([f'{b:02X}' for b in val])
            self.log(f"✅ 当前注册表指纹: {tp}")
            messagebox.showinfo("验证成功", f"注册表中的证书指纹:\n{tp}")
        except Exception as e:
            self.log(f"❌ 验证失败: {e}")
            messagebox.showerror("错误", str(e))


def main():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showerror("权限错误", "请以管理员身份运行此程序！")
            return
    except:
        pass
    root = tk.Tk()
    app = RDPCertificateGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
