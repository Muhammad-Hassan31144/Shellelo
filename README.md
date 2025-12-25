# Shellello

**Version 2.5.0** | Multi-Language Web Administration Interface

A unified, web admin tool available for multiple server-side platforms with consistent UI and functionality.

---

## 🚀 Available Editions

| Edition | File | Server Requirements | Status |
|---------|------|---------------------|--------|
| **PHP** | `index.php` | PHP 7.0+ with Apache/Nginx | ✅ Complete |
| **Go** | `go/index.go` | Go 1.21+ (standalone binary) | ✅ Complete |
| **JSP** | `jsp/index.jsp` | Java 8+, Servlet 3.0+ | ✅ Complete |
| **ASP** | `asp/index.asp` | IIS with Classic ASP | ✅ Complete |
| **C# ASHX** | `ashx/index.ashx` | IIS + .NET Framework 4.7.2+ | ✅ Complete |
| **C# ASPX** | `aspx/index.aspx` | IIS + .NET Framework 4.7.2+ | ✅ Complete |
| **JSPX** | `jspx/index.jspx` | Java 8+, Servlet 3.0+ | ✅ Complete |

---

## ✨ Features

- 🔐 **Password-Protected Access** - Secure SHA-256 hashed passwords
- 📁 **File Manager** - Browse, view, edit, upload, download, delete files
- 🗄️ **Database Client** - MySQL/PostgreSQL support with CSV export
- 💻 **Terminal** - Execute system commands with output capture
- 📊 **Dashboard** - System info, disk usage, process user
- ⚙️ **Settings** - Configuration management
- 📝 **Error Logging** - Production-safe error messages

---

## 📦 Installation

### PHP Edition
```bash
# Single file deployment - requires PHP 7.0+
cp index.php /var/www/html/admin/
```

### Go Edition
```bash
# Compile and run - single binary, no runtime needed
cd go/
go build -o shellello .
./shellello  # Runs on http://localhost:8080
```

### JSP Edition
```bash
# Deploy to servlet container
cp -r jsp/ $CATALINA_HOME/webapps/shellello/
```

### ASP Edition
```bash
# Copy to IIS virtual directory
cp -r asp/ C:\inetpub\wwwroot\shellello\
```

### C# ASHX/ASPX Editions
```powershell
# Copy to IIS application directory
copy ashx\index.ashx C:\inetpub\wwwroot\shellello\
# or
copy aspx\*.* C:\inetpub\wwwroot\shellello\
```

### JSPX Edition
```bash
# Deploy like JSP but with XML syntax
cp jspx/index.jspx $CATALINA_HOME/webapps/shellello/
```

---

## 🔑 Default Credentials

**Password:** `password`

⚠️ **IMPORTANT:** Change the password hash before deployment!

### Generating New Password Hashes

**PHP:**
```php
echo password_hash('your_new_password', PASSWORD_DEFAULT);
```

**JSP/ASP (SHA-256):**
```bash
echo -n "your_new_password" | sha256sum
```

---

## 🛡️ Security Recommendations

1. **Change default password** before deployment
2. **Use HTTPS** in production
3. **Restrict access** via IP whitelist or VPN
4. **Monitor logs** for unauthorized access attempts
5. **Keep updated** with latest security patches

---

## 📋 Platform-Specific Notes

### PHP Edition
- Requires `exec()` function for terminal features
- PDO extension needed for database connectivity
- Works with Apache, Nginx, or any PHP-compatible server

### JSP Edition
- Requires Java 8+ runtime
- JDBC drivers needed for database connections (MySQL Connector/J, PostgreSQL JDBC, etc.)
- Deploy as WAR or directly to webapps folder

### ASP Edition
- Requires Windows Server with IIS
- ODBC drivers needed for database connections
- Enable ASP in IIS features
- May need to enable `WScript.Shell` for terminal features

---

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

Use this tool responsibly. The administrators are responsible for the content and management of the sites they oversee.

---

## 📄 License

Proprietary - All Rights Reserved

---

*Built with ❤️ for web administrators*
