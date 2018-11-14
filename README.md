# Logs

Logs is a BurpSuite extension to work with log files.

Under Project Options > Misc > Logging, there are options to log every HTTP request and response made and received by BurpSuite. Logging can be configured per-tool or for all Burp traffic. This can be useful to keep complete records of your Burp session.
Whit this simple extension you will be able to load Burp log files into Burp and perfom actions like sending a specific request to the Repeater.


## Building instructions:

- Clone the repo.
- Make a couple of dirs, `bin` and `build`.
`mkdir bin build`
- Build the Logs jar.
`javac -d build/ src/burp/*.java`
`jar cf bin/Logs.jar -C build/ burp
- Load your `bin/Logs.jar` into Burp.

