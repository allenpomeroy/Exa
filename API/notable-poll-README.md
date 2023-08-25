This script uses the supported NewScale Search API to authorize and query a NewScale tenant for Notable User and Notable Asset ‘events’ that have been forwarded from Advanced Analytics back to NewScale for availability to Search, Dashboards and Reporting.  The results are forwarded to an external third-party system such as a central monitoring system within an MSSP/MDR or case management system.  Currently the forward protocol and transport is syslog TLS.  Forward by webhook is under development. 

A mandatory configuration file contains the customer tenant information such as authorization URL, base API URL, authorization token and secret, as well as destination fully qualified domain names and port for a variable number of syslog TLS destinations.  Additionally the configuration script specifies state tracking session, lock and blacklist files. 

The script is intended to run on a recurring basis and will maintain state of sessions which have already been forwarded to the specified syslog TLS destinations.

See comments in the script for requirements and cautions.
