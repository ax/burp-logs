# Log Viewer

Log Viewer 2.0 is an updated BurpSuite extension of Log Viewer 1.0 to work with log files.

Whit this simple extension you will be able to load Burp's log files into Burp, and perfom actions like sending a specific request to the Repeater to perform further attacks or analysis.

1. Load Project Misc Logs
Under Project Options > Misc > Logging, there are options to log every HTTP request and response made and received by Burp. Logging can be configured per-tool or for all Burp traffic. This can be useful to keep __complete__ records of your sessions.

2. Load Saved Items:
Requests found in Proxy History and etc can be saved via "Save item" Burp function. This new update has added the capability to parse those XML saved item.   

## Features

### Versions

Logs (Ax) / Log Viewer 1.1 (PortSwigger)
- A tab within the main Burp UI.
- A log table and two instances of Burp's own HTTP message editor, which display the selected request and response (as in the Proxy history).
- Right-clicking the message editor produces the classic Burp's context menu used to perform actions like sending the message to other Burp tools, request/show in browser, copy as curl command, etc.


Log Viewer 2.0
- Added the ability to load "Saved Items" XML data into the view.

## Building instructions
- Clone the repo.
- Using Gradle, run the following:
```
gradle build
```
- The resulting Jar file will be found at ./build/libs/log-viewer.jar
- Load this Jar file into Burp Extender.

