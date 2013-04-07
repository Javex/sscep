libscep Design Considerations
=============================
sscep is currently written as a client to be run from the command line.
However, a much cleaner solution is now in order: Split up the 
command line tool and the code executing the request. To achieve this,
multiple approaches will be taken to ensure a clean solution.

This document will give an overview over what is supposed to be happening
in the future and which aspects should be covered how.

_Note_: An important goal of this approach is that the scep command line
tool should not behave different in any way. It should continue to be used as
it was before while the internals are allowed to change.

Interface
---------
The interface will be the actual entry point for any application actually
using `libscep`. Thus, it needs to be clean, concise and should never change
once it is finished. A clean design is key to this and this document attempts
to make the first step in this direction.

### Small introduction ###
To understand what the interface needs and how it could be cleanly designed,
some information needs to be given on the client side of the SCEP protocol.

The library currently implements the following operations of the SCEP protocol:

- getca
- getnextca
- enroll
- getcrl
- getcert

`getca` requests all certificates the SCEP server considers relevant. Thus,
multiple certificates can be returned, but the first one has to be the SCEP
server's certificate.

`getnextca` requests a new CA certificate from a root rollover. (_Note_: This
needs better documentation).

`enroll` sends a CSR and possibly a signature created with an old valid
certificate. As a response it recieves a new certificate for the CSR.

`getcrl` gets the current certificate revocation list from the server.
(_Note_: Need more doc here).

`getcert` gets an existing certificate (any certificate can be requested).

All operations share a common set of configuration (e.g. the SCEP server) but
also have differences according to their actions.

### Concept ###
Based on the above introduction it is possible to develop a clean concept for
the API: An instance of an SCEP client is created once by calling an
initialization function and can be used for multiple actions at once.

The initialization function should support configuration on init and prepare
all necessary data that is valid across multiple requests. It returns a handle
for an SCEP instance. This handle is then passed to any API function that is
used.

Additionally, there should be a configuration interface to (re-)configure the
client either by option or at once. This allows for altering of configuration
options such as output filename. This also needs some form of sanity check at
a certain point to ensure that all configuration is done properly. It should
be called implicitly at a sane point (possibly before sending a request?).
It is not clear yet how this will be done.

Finally, there should be an interface for each operation. They accept a 
configuration, check it for sanity and fill the configuration with specifc
options and then execute their action. It should accept an output parameter
which specifc use depends on the type of operation. It needs to be evaluated
whether a callback function might be appropriate (this allows to handle the
returned data customly, e.g. writing to file or a buffer).

The operation returns an error code and it needs to be tested whether this is.
If an error occurred the calling problem can decide how to handle it. For
example, the command line client probably wants to use an exit code while 
a tool using the library will most likely report the error back to the 
application insead of exiting.

It is possible that the return codes can be taken from the current exit code
which would also allow the command line application to pass these errors right
through as an exit code thereby maintaining it current behaviour.

Internals
---------
Internally the implementation should remove any global variables. They are bad
and can lead to weird behaviour once more complex usage is desired. The
decition described in the `Interface` chapter to pass the handle at each call
is a lot cleaner. Any configuration etc. should be done on that handle.

Furthermore, the program should be broken down into small pieces instead of
large chunks of code in a single function. The current way it is in the `main`
function should be considered deprecated and needs to be refactored.

### Configuration ###
Any incoming configuration should be stored in a struct, possibly dividing
operation specific configuration into sub-structs or categories. Otherwise,
this might lead to confusion with operations that behave differently
depending on the operation. For example, the `-c` option denotes the 
`CA certificate file` but is the output file for operation `getca` while
being the input file for all other operations.

Further elaborating on this example, the usage of the command line is to pass
in an output filename like `cacert` for action `getca` which then writes
files `cacert-0`, `cacert-1`, etc. while the input option then is `cacert-0`
(the first cert is the SCEP server cert). As a result this could lead to 
avoidable errors and confiusion.

Configuration should be a two-step process: First, the global configuration is
done. This is where options like the SCEP server URL get passed in, parsed and
set. Second, there is operation specific configuration. This is valid for the
lifetime of a single operation (i.e. calling the function a second time
requires new configuration to be passed in.

This also leads to the option that operation-specific configuration is cleared
after the operation has executed. Whether this is necessary has not beed 
decided yet.

### ... ###
... Todo ...
