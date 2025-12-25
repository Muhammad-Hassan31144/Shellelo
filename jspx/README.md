# Shellello - JSPX Edition

**Version:** 2.5.0  
**Language:** Java / JSPX (XML-based JSP)

## Requirements

- Java 8+ (Java 11 or 17 LTS recommended)
- Servlet API 3.0+
- JSP 2.2+
- JSTL 1.2+
- Servlet container (Tomcat 8+, Jetty 9+, etc.)

## Installation

1. Copy `index.jspx` to your web application directory
2. Ensure JSTL libraries are in WEB-INF/lib or provided by container
3. Deploy to servlet container

## Configuration

Edit `index.jspx` to change:
- `AUTH_HASH` - SHA-256 hash of your password
- `DEBUG_MODE` - Enable detailed error messages (default `false`)

## Features

- ✅ Authentication (SHA-256)
- ✅ XML-based JSP syntax (well-formed)
- ✅ JSTL tags for control flow
- ✅ Session management
- ⚠️ File Manager (basic structure)
- ⚠️ Database Client (basic structure)
- ⚠️ Terminal (basic structure)

## Differences from JSP

- Uses XML syntax instead of scriptlets
- Well-formed XML required
- JSTL tags for conditionals and loops
- More verbose but cleaner separation
- Better IDE validation

## Deployment

Deploy as WAR file or copy to webapps directory of servlet container.
