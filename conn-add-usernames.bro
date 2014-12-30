module Auth;

export {
	redef record Conn::Info += { 
		## List of users associated with the originator.
		orig_users: set[string]				&log &optional;
		## List of users associated with the responder.
		resp_users: set[string]				&log &optional;
	};
}

function add_orig_users(c: connection)
	{
	local orig_users: set[string];
	local auth_records = get_users([$host=c$id$orig_h]);
	for ( rec in auth_records )
		{
		add orig_users[rec$username];
		}
	if ( |orig_users| > 0 )
		c$conn$orig_users = orig_users;
	}

function add_resp_users(c: connection)
	{
	local resp_users: set[string];
	local auth_records = get_users([$host=c$id$resp_h]);
	for ( rec in auth_records )
		{
		add resp_users[rec$username];
		}
	if ( |resp_users| > 0 )
		c$conn$resp_users = resp_users;
	}

event connection_state_remove(c: connection)
	{
	add_orig_users(c);
	add_resp_users(c);
	}
