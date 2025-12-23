# Shellello / WebAdmin Pro Architecture

## Overview
This document outlines the architecture for the single-file web administration tool described in the project blueprint. The application is designed to be a self-contained, lightweight, and professional-looking interface for server management.

## Design Philosophy
- **Single File Deployment:** All logic, styling (CSS), and client-side behavior (JS) are embedded within a single PHP file (`index.php`) to ensure easy deployment and portability.
- **Professional UI:** A clean, modern interface that mimics legitimate administration dashboards to provide a comfortable user experience.
- **Modularity:** Functionality is segregated into logical modules (File Manager, Database, Terminal) within the code structure, even though physically located in one file.

## Core Components

### 1. Authentication Layer
- **Mechanism:** Session-based authentication protected by a strong password hash.
- **Security:** 
  - `password_verify` for credential checking.
  - Session token generation (`bin2hex(random_bytes(32))`) to prevent session fixation/hijacking.
  - Login gate that blocks access to all other modules until authenticated.

### 2. Application Controller (Main Loop)
- **Routing:** A central dispatcher determines which module or action to execute based on query parameters (e.g., `?page=files`, `?action=upload`).
- **Response Handling:** Returns either HTML for page loads or JSON for AJAX requests (used by the File Manager and Terminal).

### 3. Modules

#### A. Dashboard
- **Purpose:** Provides a high-level overview of the system.
- **Features:** System status, shortcuts to other modules, and quick stats.

#### B. File Manager
- **Purpose:** Browse and manipulate the server's file system.
- **Capabilities:**
  - List directories and files with metadata (size, permissions, modified date).
  - Read and write file contents.
  - Upload files (handling `$_FILES`).
  - *Implementation Note:* Uses PHP's native filesystem functions (`opendir`, `file_get_contents`, `file_put_contents`).

#### C. Database Explorer
- **Purpose:** Manage database connections and execute queries.
- **Capabilities:**
  - Support for multiple drivers (MySQL, PostgreSQL, SQLite).
  - Query execution interface.
  - Table listing and data viewing.

#### D. System Terminal
- **Purpose:** Execute system commands directly from the browser.
- **Capabilities:**
  - Interface to run shell commands.
  - Output capture and display.
  - *Security Note:* This feature requires careful handling to prevent unauthorized access if the authentication is compromised.

### 4. Frontend Architecture
- **CSS:** Embedded styles using CSS variables for theming (Dark/Light modes).
- **JavaScript:** 
  - `WebAdminApp` class to handle tab switching and state management.
  - `FileManager` class for AJAX-based file operations.
  - Fetch API used for communication with the backend.

## Data Flow
1. **Request:** User accesses `index.php`.
2. **Auth Check:** System checks `$_SESSION['authenticated']`. If false, renders Login Page.
3. **Routing:** If authenticated, checks `$_GET['page']` or `$_GET['action']`.
4. **Processing:** Calls the relevant PHP function (e.g., `handleFileManager()`).
5. **Output:** Renders the specific view (HTML) or returns data (JSON).

## Security Considerations
- **Input Validation:** All user inputs (paths, queries, commands) must be sanitized.
- **CSRF Protection:** Anti-CSRF tokens should be verified on state-changing actions.
- **Error Handling:** Errors should be logged but not displayed verbosely to avoid information leakage.
