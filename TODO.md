# fencedns TODO list

Features:

* IPv6 support
* don't send 2nd duplicate request to an upstream server
* hosts:

		analyze_response_cname_hosts true

* clients map: use id-type-name key
* ignore requests from unwanted clients

		clients_allow {
			127.0.0.1
		}
		clients_block {
			0.0.0.0
		}

Build:

* build for Windows
	* Windows service code
* build for ARM
