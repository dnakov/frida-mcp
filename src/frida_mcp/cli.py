#!/usr/bin/env python3
"""
Command line entry point specifically for Claude Desktop integration.

This script is designed to be the target of the command in claude_desktop_config.json.
It sets up a basic Frida MCP server with STDIO transport for Claude to communicate with.
"""

import sys
import ipaddress
import frida
from mcp.server.fastmcp import FastMCP, Context
from typing import Dict, List, Optional, Any, Union
import threading
import time
from pydantic import Field

# Create the MCP server
mcp = FastMCP("Frida")

# Global dictionary to store scripts and their messages
# This allows us to retrieve messages from scripts after they've been created
_scripts = {}
_script_messages = {}
_message_locks = {}
global_persistent_scripts = {} # Added for managing persistent scripts


@mcp.tool()
def enumerate_processes(
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device to enumerate processes from. Uses USB device if not specified.")
) -> List[Dict[str, Any]]:
    """List all processes running on the system.
    
    Returns:
        A list of process information dictionaries containing:
        - pid: Process ID
        - name: Process name
    """
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device()
    processes = device.enumerate_processes()
    return [{"pid": process.pid, "name": process.name} for process in processes]


@mcp.tool()
def enumerate_devices() -> List[Dict[str, Any]]:
    """List all devices connected to the system.
    
    Returns:
        A list of device information dictionaries containing:
        - id: Device ID
        - name: Device name
        - type: Device type
    """
    devices = frida.enumerate_devices()
    return [
        {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
        for device in devices
    ]


@mcp.tool()
def get_device(device_id: str = Field(description="The ID of the device to get")) -> Dict[str, Any]:
    """Get a device by its ID.
    
    Returns:
        Information about the device
    """
    try:
        device = frida.get_device(device_id)
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
    except frida.InvalidArgumentError:
        raise ValueError(f"Device with ID {device_id} not found")


@mcp.tool()
def get_usb_device() -> Dict[str, Any]:
    """Get the USB device connected to the system.
    
    Returns:
        Information about the USB device
    """
    try:
        device = frida.get_usb_device()
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
    except frida.InvalidArgumentError:
        raise ValueError("No USB device found")


@mcp.tool()
def get_local_device() -> Dict[str, Any]:
    """Get the local device.
    
    Returns:
        Information about the local device
    """
    try:
        device = frida.get_local_device()
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
    except frida.InvalidArgumentError: # Or other relevant Frida exceptions
        raise ValueError("No local device found or error accessing it.")


def _format_address(host: str, port: int) -> str:
    """Format a host:port address string, correctly bracketing IPv6 addresses."""
    bare = host.strip("[]")
    try:
        addr = ipaddress.ip_address(bare)
        if isinstance(addr, ipaddress.IPv6Address):
            return f"[{bare}]:{port}"
    except ValueError:
        pass
    return f"{bare}:{port}"


@mcp.tool()
def add_remote_device(
    host: str = Field(description="The hostname or IP address of the remote Frida server (e.g. '192.168.1.100' or 'myhost')."),
    port: int = Field(default=27042, description="The port of the remote Frida server. Defaults to 27042."),
    certificate: Optional[str] = Field(default=None, description="Optional TLS certificate to use for the connection."),
    origin: Optional[str] = Field(default=None, description="Optional origin header to use for the connection."),
    token: Optional[str] = Field(default=None, description="Optional authentication token for the remote device."),
    keepalive_interval: Optional[int] = Field(default=None, description="Optional keepalive interval in seconds.")
) -> Dict[str, Any]:
    """Connect to a remote Frida server by hostname and port.

    Once added, the remote device will appear in enumerate_devices() and can be
    referenced by its device_id in all other tools.

    Returns:
        Information about the remote device including its device_id
    """
    try:
        address = _format_address(host, port)
        manager = frida.get_device_manager()

        kwargs: Dict[str, Any] = {}
        if certificate is not None:
            kwargs["certificate"] = certificate
        if origin is not None:
            kwargs["origin"] = origin
        if token is not None:
            kwargs["token"] = token
        if keepalive_interval is not None:
            kwargs["keepalive_interval"] = keepalive_interval

        device = manager.add_remote_device(address, **kwargs)
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
            "address": address,
        }
    except Exception as e:
        raise ValueError(f"Failed to add remote device at {host}:{port}: {str(e)}") from e


@mcp.tool()
def remove_remote_device(
    host: str = Field(description="The hostname or IP address of the remote Frida server to disconnect from."),
    port: int = Field(default=27042, description="The port of the remote Frida server. Defaults to 27042.")
) -> Dict[str, Any]:
    """Disconnect from a previously added remote Frida server.

    Returns:
        Status information
    """
    try:
        address = _format_address(host, port)
        manager = frida.get_device_manager()
        manager.remove_remote_device(address)
        return {"success": True, "address": address}
    except Exception as e:
        raise ValueError(f"Failed to remove remote device at {host}:{port}: {str(e)}") from e


@mcp.tool()
def get_process_by_name(name: str = Field(description="The name (or part of the name) of the process to find. Case-insensitive."),
                       device_id: Optional[str] = Field(default=None, description="Optional ID of the device to search the process on. Uses USB device if not specified.")) -> dict:
    """Find a process by name."""
    if device_id:
        device = frida.get_device(device_id)
    else:
        device = frida.get_usb_device()
    for proc in device.enumerate_processes():
        if name.lower() in proc.name.lower():
            return {"pid": proc.pid, "name": proc.name, "found": True}
    return {"found": False, "error": f"Process '{name}' not found"}


@mcp.tool()
def attach_to_process(
    pid: int = Field(description="The ID of the process to attach to."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device where the process is running. Uses USB device if not specified.")
) -> dict:
    """Attach to a process by ID."""
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
        session = device.attach(pid)
        return {
            "pid": pid,
            "success": True,
            "is_detached": False  # New session is not detached
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def spawn_process(
    program: str = Field(description="The program or application identifier to spawn."), 
    args: Optional[List[str]] = Field(default=None, description="Optional list of arguments for the program."), 
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device where the program should be spawned. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Spawn a program.
    
    Returns:
        Information about the spawned process
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
            
        pid = device.spawn(program, args=args or [])
        
        return {"pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to spawn {program}: {str(e)}")


@mcp.tool()
def resume_process(
    pid: int = Field(description="The ID of the process to resume."), 
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device where the process is running. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Resume a process by ID.
    
    Returns:
        Status information
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
            
        device.resume(pid)
        
        return {"success": True, "pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to resume process {pid}: {str(e)}")


@mcp.tool()
def kill_process(
    pid: int = Field(description="The ID of the process to kill."), 
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device where the process is running. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Kill a process by ID.
    
    Returns:
        Status information
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
            
        device.kill(pid)
        
        return {"success": True, "pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to kill process {pid}: {str(e)}")


@mcp.resource("frida://version")
def get_version() -> str:
    """Get the Frida version."""
    return frida.__version__


@mcp.resource("frida://processes")
def get_processes_resource() -> str:
    """Get a list of all processes from the USB device as a readable string."""
    device = frida.get_usb_device()
    processes = device.enumerate_processes()
    return "\n".join([f"PID: {p.pid}, Name: {p.name}" for p in processes])


@mcp.resource("frida://devices")
def get_devices_resource() -> str:
    """Get a list of all devices as a readable string."""
    devices = frida.enumerate_devices()
    return "\n".join([f"ID: {d.id}, Name: {d.name}, Type: {d.type}" for d in devices])


@mcp.tool()
def create_interactive_session(
    process_id: int = Field(description="The ID of the process to attach to for creating an interactive session."),
    device_id: Optional[str] = Field(default=None, description="Optional ID of the device where the process is running. Uses USB device if not specified.")
) -> Dict[str, Any]:
    """Create an interactive REPL-like session with a process.
    
    This returns a session ID that can be used with execute_in_session to run commands.
    
    Returns:
        Information about the created session
    """
    try:
        # Attach to process
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
        session = device.attach(process_id)
        
        # Generate a unique session ID
        session_id = f"session_{process_id}_{int(time.time())}"
        
        # Store the session
        _scripts[session_id] = session
        _script_messages[session_id] = []
        _message_locks[session_id] = threading.Lock()
        
        return {
            "status": "success",
            "process_id": process_id,
            "session_id": session_id,
            "message": f"Interactive session created for process {process_id}. Use execute_in_session to run JavaScript commands."
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def execute_in_session(
    session_id: str = Field(description="The unique identifier of the active Frida session. This ID is obtained when the session is first created."), 
    javascript_code: str = Field(description="A string containing the JavaScript code to be executed in the target process\'s context. The script can use Frida\'s JavaScript API (e.g., Interceptor, Memory, Module, rpc)."), 
    keep_alive: bool = Field(default=False, description="A boolean flag indicating whether the script should remain loaded in the target process after its initial execution. If False (default), the script is unloaded after initial run. If True, it persists for hooks/RPC and messages are retrieved via get_session_messages. Note: With keep_alive=True, JavaScript code should manage log volume (limits, deduplication) to prevent too many messages.")
) -> Dict[str, Any]:
    """Execute JavaScript code within an existing interactive Frida session.

    This tool allows for dynamic scripting against a process previously attached to
    via `create_interactive_session`.
    """
    if session_id not in _scripts:
        raise ValueError(f"Session with ID {session_id} not found")
    
    session = _scripts[session_id]
    lock = _message_locks[session_id]

    try:
        # For interactive use, we need to handle console.log output
        # and properly format the result
        
        # Wrap the code to capture console.log output and return values
        # This basic wrapper sends back immediate script result/errors and console.log output
        # For keep_alive=True, subsequent messages from the script (e.g., from Interceptor)
        # will be handled by the persistent on_message handler.
        wrapped_code = f"""
        (function() {{
            var initialLogs = [];
            var originalLog = console.log;
            
            console.log = function() {{
                var args = Array.prototype.slice.call(arguments);
                var logMsg = args.map(function(arg) {{
                    return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
                }}).join(' ');
                initialLogs.push(logMsg);
                originalLog.apply(console, arguments); // Also keep original console behavior
            }};
            
            var scriptResult;
            var scriptError;
            try {{
                scriptResult = eval({javascript_code!r});
            }} catch (e) {{
                scriptError = {{ message: e.toString(), stack: e.stack }};
            }}
            
            console.log = originalLog; // Restore
            
            send({{ // This send is for the initial execution result
                type: 'execution_receipt',
                result: scriptError ? undefined : (scriptResult !== undefined ? scriptResult.toString() : 'undefined'),
                error: scriptError,
                initial_logs: initialLogs
            }});
        }})();
        """
        
        script = session.create_script(wrapped_code)
        
        # This list captures messages from the initial execution of the script (the wrapper)
        initial_execution_results = [] 
        
        def on_initial_message(message, data):
            # This handler is for the initial execution wrapper's send()
            if message["type"] == "send" and message["payload"]["type"] == "execution_receipt":
                initial_execution_results.append(message["payload"])
            elif message["type"] == "error": # Script compilation/syntax errors
                initial_execution_results.append({"script_error": message["description"], "details": message})

        # This handler is for persistent messages if keep_alive is true
        def on_persistent_message(message, data):
            with lock:
                _script_messages[session_id].append({"type": message["type"], "payload": message.get("payload"), "data": data})

        if keep_alive:
            # For keep_alive, messages go to the global queue _script_messages
            # The script object itself will handle these.
            script.on("message", on_persistent_message)
            # Store the script object if we need to interact with it later (e.g., specific unload)
            # For now, it's attached to the session and will be cleaned up when session is detached or process ends.
            if session_id not in global_persistent_scripts: # Requires global_persistent_scripts dict
                global_persistent_scripts[session_id] = []
            global_persistent_scripts[session_id].append(script)

        else:
            # For non-persistent scripts, use the local handler for immediate results
            script.on("message", on_initial_message)
        
        script.load()
        
        # For non-persistent scripts, give a short time for the initial_execution_results
        # For persistent scripts, this sleep is less critical as it's about setting up.
        if not keep_alive:
            time.sleep(0.2) # Slightly increased for safety

        # Process initial results (for both modes, but primarily for non-keep_alive)
        final_result = {}
        if initial_execution_results:
            # Use the first message from the execution_receipt
            receipt = initial_execution_results[0]
            if "script_error" in receipt:
                 final_result = {
                    "status": "error",
                    "error": "Script execution error",
                    "details": receipt["script_error"]
                }
            elif receipt.get("error"):
                final_result = {
                    "status": "error",
                    "error": receipt["error"]["message"],
                    "stack": receipt["error"]["stack"],
                    "initial_logs": receipt.get("initial_logs", [])
                }
            else:
                final_result = {
                    "status": "success",
                    "result": receipt["result"],
                    "initial_logs": receipt.get("initial_logs", [])
                }
        elif keep_alive:
             final_result = {
                "status": "success",
                "message": "Script loaded persistently. Use get_session_messages to retrieve asynchronous messages.",
                "initial_logs": []
            }
        else: # No messages received, could be an issue or just a silent script
            final_result = {
                "status": "nodata", # Or "success" if empty result is fine
                "message": "Script loaded but sent no initial messages.",
                "initial_logs": []
            }

        if not keep_alive:
            script.unload()
            final_result["script_unloaded"] = True
        else:
            final_result["script_unloaded"] = False
            final_result["info"] = "Script is persistent. Remember to manage its lifecycle if necessary."

        return final_result
    
    except frida.InvalidOperationError as e: # E.g. session detached
        return {"status": "error", "error": f"Frida operation error: {str(e)} (Session may be detached)"}
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def get_session_messages(
    session_id: str = Field(description="The ID of the session to retrieve messages from.")
) -> Dict[str, Any]:
    """Retrieve and clear messages sent by persistent scripts in a session.
    
    Returns:
        A list of messages captured since the last call, or an error if the session is not found.
    """
    if session_id not in _scripts:
        # Check if it was a session that had persistent scripts but might have been cleared or detached
        if session_id in global_persistent_scripts and not global_persistent_scripts[session_id]:
             return {"status": "success", "messages": [], "info": "Session had persistent scripts that might be finished or detached."}
        raise ValueError(f"Session with ID {session_id} not found or no persistent scripts active.")

    if session_id not in _message_locks or session_id not in _script_messages:
        # This case should ideally not happen if session_id is in _scripts from create_interactive_session
        return {"status": "error", "error": f"Message queue or lock not found for session {session_id}."}

    lock = _message_locks[session_id]
    with lock:
        messages = list(_script_messages[session_id])  # Make a copy
        _script_messages[session_id].clear()  # Clear the queue
        
    return {
        "status": "success",
        "session_id": session_id,
        "messages_retrieved": len(messages),
        "messages": messages
    }


def main():
    """Run the CLI entry point for Claude Desktop integration."""
    mcp.run()


if __name__ == "__main__":
    main() 