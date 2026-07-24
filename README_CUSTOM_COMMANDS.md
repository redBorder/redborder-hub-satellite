# Redborder Satellite Custom Command Execution Engine

The **Custom Command Execution Engine** allows administrators to extend `redborder-satellite` with custom tasks—such as executing configuration management agents (`chef-client`), controlling system services, running maintenance scripts, or reading log files—without modifying any Go code or introducing Remote Code Execution (RCE) vulnerabilities.

---

## Security Architecture

1. **Direct `execve` System Calls (No Shell Wrappers)**:
   Commands are executed directly via Go's `exec.CommandContext`, invoking the OS kernel `execve` syscall directly. No shell (`sh -c` or `bash -c`) is ever spawned. Shell injection operators (`;`, `|`, `&&`, `$()`, backticks) are completely inert and harmless.

2. **Administrator-Controlled Whitelist**:
   The Hub cannot request arbitrary binaries or unapproved scripts. It can only trigger method names that the local Satellite administrator has explicitly declared in `satellite.json`.

3. **Strict Input Sanitization (`param_rules`)**:
   Dynamic parameters passed over JSON-RPC are validated against strict regex rules or fixed value whitelists before being passed to binaries.

4. **Path Traversal Protection (`type: "file_read"`)**:
   File-reading commands enforce wildcard pattern matching (`allowed_paths`) and canonical path resolution (`filepath.Clean`), preventing unauthorized reads of system files like `/etc/shadow`.

---

## Configuration Reference (`satellite.json`)

To enable custom commands, add a `"commands"` dictionary to `/etc/redborder-satellite/satellite.json`:

```json
{
  "hub_url": "ws://localhost:8080/ws",
  "agent_id": "remote-satellite-01",
  "commands": {
    "COMMAND_NAME": {
      "type": "file_read",
      "executable": "/path/to/binary",
      "args": ["flag1", "$param_name"],
      "param_rules": {
        "param_name": {
          "regex": "^[a-zA-Z0-9_\\-]+$",
          "allowed_values": ["val1", "val2"],
          "required": true
        }
      },
      "allowed_paths": ["/var/log/*.log"],
      "max_bytes": 1048576,
      "timeout_seconds": 60,
      "env": ["ENV=production"]
    }
  }
}
```

### Configuration Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | string | `""` (default, binary execution) or `"file_read"` (safe file reader). |
| `executable` | string | Absolute path to the binary or script to execute (e.g. `/usr/bin/chef-client`). |
| `args` | array | Arguments slice. Supports `$param_name` place-holders for dynamic RPC params. |
| `param_rules` | object | Validation rules for incoming RPC parameters (key = parameter name). |
| `allowed_paths`| array | *(file_read only)* Wildcard glob patterns of permitted file paths. |
| `max_bytes` | integer| Maximum bytes to read from file or keep from stdout/stderr (default: 512 KB). |
| `timeout_seconds`| integer| Maximum execution duration before SIGKILL (default: 60s). |
| `env` | array | Extra environment variables passed to the process (e.g. `["FOO=bar"]`). |

### Parameter Validation Rules (`param_rules`)

| Rule Property | Type | Description |
| :--- | :--- | :--- |
| `regex` | string | Regular expression that the parameter value must match. |
| `allowed_values` | array | Fixed whitelist of permitted string values. |
| `required` | boolean | If `true`, the command fails if the parameter is missing. |

---

## Complete Usage Examples

### 1. Chef Client Execution (`chef_client`)
Run `chef-client` on-demand or on schedule:

```json
"chef_client": {
  "executable": "/usr/bin/chef-client",
  "args": ["--once", "--log_level", "info"],
  "timeout_seconds": 300
}
```

**Dispatch via `curl`:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{
  "agent_id": "remote-satellite-01",
  "method": "chef_client",
  "params": {}
}' http://localhost:8080/dispatch
```

---

### 2. Service Control (`service_ctl`)
Safely restart or check system services (`systemctl`):

```json
"service_ctl": {
  "executable": "/usr/bin/systemctl",
  "args": ["$action", "$service"],
  "param_rules": {
    "action": {
      "allowed_values": ["status", "restart", "reload"],
      "required": true
    },
    "service": {
      "regex": "^[a-zA-Z0-9_\\-]+$",
      "required": true
    }
  },
  "timeout_seconds": 30
}
```

**Dispatch via `curl`:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{
  "agent_id": "remote-satellite-01",
  "method": "service_ctl",
  "params": {
    "action": "restart",
    "service": "nginx"
  }
}' http://localhost:8080/dispatch
```

---

### 3. Package Management (`package_mgr`)
Safely update or check software packages via `dnf`:

```json
"package_mgr": {
  "executable": "/usr/bin/dnf",
  "args": ["$action", "-y", "$package"],
  "param_rules": {
    "action": {
      "allowed_values": ["update", "check-update", "info"],
      "required": true
    },
    "package": {
      "regex": "^[a-zA-Z0-9_\\-\\.]+$"
    }
  },
  "timeout_seconds": 600
}
```

**Dispatch via `curl`:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{
  "agent_id": "remote-satellite-01",
  "method": "package_mgr",
  "params": {
    "action": "update",
    "package": "redborder-satellite"
  }
}' http://localhost:8080/dispatch
```

---

### 4. Log / File Reader (`cat_log`)
Read log files safely while enforcing wildcard pattern boundaries:

```json
"cat_log": {
  "type": "file_read",
  "allowed_paths": [
    "/var/log/redborder/*.log",
    "/var/log/syslog"
  ],
  "max_bytes": 524288
}
```

**Dispatch via `curl`:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{
  "agent_id": "remote-satellite-01",
  "method": "cat_log",
  "params": {
    "path": "/var/log/redborder/satellite.log"
  }
}' http://localhost:8080/dispatch
```

---

### 5. Custom Script Execution (`custom_script`)
Execute an internal maintenance script with custom environment variables:

```json
"custom_script": {
  "executable": "/opt/scripts/healthcheck.sh",
  "args": ["--mode", "$mode"],
  "param_rules": {
    "mode": {
      "allowed_values": ["quick", "full"]
    }
  },
  "env": ["ENVIRONMENT=production"],
  "timeout_seconds": 60
}
```

---

## Response Payloads

### Binary Execution Response (`type: ""`)

```json
{
  "jsonrpc": "2.0",
  "result": {
    "executable": "/usr/bin/systemctl",
    "args": ["restart", "nginx"],
    "exit_code": 0,
    "duration_ms": 142,
    "stdout": "Job for nginx.service succeeded.\n",
    "stderr": ""
  },
  "id": "dispatch-1"
}
```

### File Reader Response (`type: "file_read"`)

```json
{
  "jsonrpc": "2.0",
  "result": {
    "path": "/var/log/syslog",
    "size_bytes": 1048576,
    "read_bytes": 524288,
    "content": "2026-07-20T14:00:00 systemd[1]: Started Satellite Service...\n",
    "truncated": true
  },
  "id": "dispatch-2"
}
```

---

## Scheduling Custom Commands

Custom commands can also be scheduled centrally from the Hub via the `/schedules` REST API.

Example: Schedule `chef_client` to run every 6 hours (21600 seconds):

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{
  "id": "chef-client-schedule",
  "agent_id": "remote-satellite-01",
  "method": "chef_client",
  "schedule_type": "interval",
  "interval_seconds": 21600,
  "params": {}
}' http://localhost:8080/schedules
```
