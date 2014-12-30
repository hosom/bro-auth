module Auth;

event RADIUS::log_radius(rec: RADIUS::Info)
	{
	if ( rec?$username )
		{
		local i = Info($ts=rec$ts,
						$username=rec$username,
						$endpoint=Endpoint($mac=rec$mac),
						$service="Network Access",
						$method="Radius");
		if ( rec$result == "failed" )
			i$success = F;

		handle_login(i);
		}
	}


event DHCP::log_dhcp(rec: DHCP::Info)
	{
	local e: Endpoint;
	if ( rec?$assigned_ip )
		e$host = rec$assigned_ip;
	if ( rec?$mac )
		e$mac = rec$mac;

	local records_to_update = get_users(e);	

	if ( |records_to_update| > 0 )
		{
		for ( old_rec in records_to_update )
			{
			local new_rec = Info($ts=old_rec$ts, 
								$username=old_rec$username,
								$endpoint=e,
								$service=old_rec$service,
								$method=old_rec$method,
								$success=old_rec$success);
			modify_login(old_rec, new_rec);
			}
		}
	}
