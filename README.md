This repository contains a script to detect potentially suspicious unsigned processes running on Linux systems by examining `/proc` entries and checking for executables in temporary locations.

## Overview

The `Detect-unsigned-Processes.sh` script scans running processes through the `/proc` filesystem, identifying processes that either:
- Have missing executable files
- Are running from temporary directories (/tmp, /var/tmp, /dev/shm)

The script provides standardized logging and JSON output suitable for integration with security orchestration platforms, SIEM systems, and incident response workflows.

## Script Structure

### Core Components

1. **Logging Framework** - Comprehensive logging with rotation
2. **Error Handling** - Basic exception management  
3. **JSON Output** - Standardized response format with proper escaping
4. **Execution Timing** - Performance monitoring
5. **Process Detection** - /proc scanning and analysis

## How Script Is Invoked

### Command Line Execution

./Detect-unsigned-Processes.sh

Environment Variables
Variable	Description
VERBOSE	Set to 1 to enable debug logging
LogPath	Override default log path (/tmp/Detect-Unsigned-Processes-script.log)
ARLog	Override default active response log path (/var/ossec/active-response/active-responses.log)
Script Functions
Write-Log

Purpose: Provides standardized logging with multiple severity levels and console output.

Parameters:

    Message (string): The log message to write

    Level (string): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

Features:

    Timestamp formatting

    Color-coded console output based on severity

    File logging with structured format

    Verbose debugging support

Usage:
bash

WriteLog "Process scan started" "INFO"
WriteLog "Permission denied on /proc entry" "WARN" 
WriteLog "Critical error occurred" "ERROR"
WriteLog "Debug information" "DEBUG"

Rotate-Log

Purpose: Manages log file size and implements automatic log rotation.

Features:

    Monitors log file size (default: 100KB threshold)

    Maintains configurable number of historical log files (default: 5)

    Automatic rotation when size limit exceeded

Configuration Variables:

    LogMaxKB: Maximum log file size in KB before rotation (default: 100)

    LogKeep: Number of rotated log files to retain (default: 5)

escape_json

Purpose: Properly escapes strings for JSON output to prevent formatting issues.
Script Execution Flow
1. Initialization Phase

    Log rotation check and execution

    Active response log clearing

    Script start logging with timestamp

2. Process Scanning Phase

    Iterates through /proc/[0-9]* directories

    Extracts process command line and executable path

    Checks for suspicious conditions:

        Missing executable file

        Executable in temp directory (/tmp, /var/tmp, /dev/shm)

3. Output Generation Phase

    Builds JSON array of suspicious processes

    Includes PID, command, executable path, and reason

    Properly escapes all strings for JSON output

4. Completion Phase

    JSON result formatting and output

    Active response log writing

    Execution duration calculation

JSON Output Format

The script outputs standardized JSON responses to the active response log:
Example Response with Findings
json

{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-Unsigned-Processes",
  "data": [
    {
      "pid": 1234,
      "cmd": "./malicious-script",
      "exe": "/tmp/malicious-script",
      "reason": "Executable in temp directory"
    },
    {
      "pid": 5678, 
      "cmd": "[kworker/0:1]",
      "exe": "",
      "reason": "Executable missing"
    }
  ],
  "copilot_soar": true
}

Example Empty Response
json

{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME", 
  "action": "Detect-Unsigned-Processes",
  "data": [],
  "copilot_soar": true
}

Implementation Guidelines
1. Customizing Detection Logic

    Modify the suspicious process detection criteria in the main loop

    Add additional checks as needed (e.g., file signatures, hashes)

    Update the JSON output structure to include new fields

2. Best Practices

    Run with appropriate privileges to access /proc entries

    Consider performance impact on busy systems

    Monitor script execution time

    Test thoroughly in your environment

3. Integration Considerations

    Ensure SIEM can parse the JSON output format

    Consider rate limiting if running frequently

    May need to whitelist known temporary executables

Security Considerations

    Script requires read access to /proc filesystem

    Be cautious about logging sensitive command-line arguments

    Consider adding hash verification of executables

    May generate false positives for legitimate temp executables

Troubleshooting
Common Issues

    Permission Errors: Ensure script has access to /proc entries

    Missing Processes: Some processes may hide from /proc

    False Positives: Legitimate programs may run from temp directories

    Performance Impact: Scanning all processes may be resource intensive

Debug Mode

Enable verbose logging to see detailed scan information:
bash

VERBOSE=1 ./Detect-unsigned-Processes.sh

License

This script is provided as-is for security automation and incident response purposes.
text


This template is provided as-is for security automation and incident response purposes.
