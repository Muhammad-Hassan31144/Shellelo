# Shellello - C# ASPX Edition

**Version:** 2.5.0  
**Language:** C# / ASP.NET Web Forms

## Requirements

- .NET Framework 4.7.2+ or .NET Core 3.1+ / .NET 6+
- IIS or ASP.NET Development Server

## Installation

1. Copy `index.aspx` and `index.aspx.cs` to your IIS application directory
2. Configure IIS for ASP.NET
3. Set appropriate file permissions

## Configuration

Edit `index.aspx.cs` to change:
- `AuthHash` - SHA-256 hash of your password
- `DebugMode` - Enable detailed error messages (default `false`)

## Features

- ✅ Authentication (SHA-256)
- ✅ File Manager (basic)
- ✅ Database Client (basic)
- ✅ Terminal (basic)
- ✅ Dashboard (system info)
- ✅ Session management
- ✅ Error logging

## Deployment

Copy both files to IIS and configure application pool.
