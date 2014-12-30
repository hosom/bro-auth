module Auth;

export {
        ## IP Addresses that send Palo Alto Firewall logs
        const panos_log_sources: set[addr] &redef;
        ## IP Addresses that receive Palo Alto Firewall logs
        const panos_log_recipients: set[addr] &redef;
		## Interval of inactivity to wait where not seeing an IP means 
		## that a user has "Logged out" from the network.
		const panos_auth_expire_interval = 15min &redef;
}

function expire(s: set[addr, string], idx: any): interval
    {
	local a: addr;
	local user: string;

	[a, user] = idx;
	local auth_records = get_systems(user);
	for ( rec in auth_records ) 
		{
		if ( rec$endpoint?$host && rec$endpoint$host == a && rec$method == "Palo Alto")
			handle_logout(rec);
		}

    return 0secs;
    }

global palo_alto_users: set[addr, string] &read_expire=panos_auth_expire_interval &expire_func=expire &synchronized;

function process_auth(a: string, user: string)
        {
		if ( a != "" && user != "" )
			{
			local host = to_addr(a);
			if ( [host, user] !in palo_alto_users )
				{
				local i = Info($ts=network_time(),
								$username=user,
								$endpoint=Endpoint($host=host),
								$service="Network Access",
								$method="Palo Alto");
				add palo_alto_users[host, user];
        		handle_login(i);
				}
			}
        }

event syslog_message(c: connection, facility: count, severity: count, msg: string)
        {
        if ( c$id$orig_h in panos_log_sources && c$id$resp_h in panos_log_recipients )
                {
				# Fields :
				# 4: The Log Message Type.
				# 8: Originating IP Address.
				# 9: Responding IP Address.
				# 13: Originating User.
				# 14: Responding User.
                local fields = split(msg, /,/);
				if ( fields[4] == "TRAFFIC" || fields[4] == "THREAT" )
					{
					process_auth(fields[8], fields[13]);
					process_auth(fields[9], fields[14]);
					}
                }
        }

