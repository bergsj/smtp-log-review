# SMTP-Log-Review
Review your Exchange Server SMTP connector receive logs

This script will loop through all the SMTP recieve logs from the on-premises Exchange Server and group the IP addresses by the SMTP connectors that they use and export this data to an output file.

You can also use the -ReverseLookup option to perform a reverse DNS lookup on the unique list of found IP addresses. These will be exported to a separate output file.