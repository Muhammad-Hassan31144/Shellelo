# Shellello

**Version 2.4.0** | Single-File Web Administration Interface

A unified, proprietary web admin tool available for multiple server-side platforms.

---

## 🚀 Available Editions

| Edition | File | Server Requirements |
|---------|------|---------------------|
| **PHP** | `index.php` | PHP 7.4+ with Apache/Nginx |
| **JSP** | `jsp/index.jsp` | Java Servlet Container (Tomcat, Jetty, etc.) |
| **ASP** | `asp/index.asp` | IIS with Classic ASP enabled |

---

## ✨ Features

- 🔐 **Password-Protected Access** - Secure login with hashed passwords
- 📁 **File Manager** - Browse, view, and edit server files
- 🗄️ **Database Client** - Connect to MySQL, PostgreSQL, SQL Server
- 💻 **Terminal** - Execute system commands directly
- 📊 **Dashboard** - System info and quick stats
- ⚙️ **Settings** - Configuration management

---

## 📦 Installation

### PHP Edition
```bash
# Just drop index.php in your web root
cp index.php /var/www/html/admin/
```

### JSP Edition
```bash
# Deploy to your servlet container's webapps directory
cp -r jsp/ $CATALINA_HOME/webapps/shellello/
```

### ASP Edition
```bash
# Copy to IIS virtual directory with ASP enabled
cp -r asp/ C:\inetpub\wwwroot\shellello\
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
