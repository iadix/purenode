struct pnpgw
{
	struct string	desc_url;
	struct string	control_path;
	struct string	control_url;
	struct string	desc;
	struct string	ex_ip;
};

LIBBASE_API int		C_API_FUNC forwardPort			(struct string *port_str);
LIBBASE_API int		C_API_FUNC broadcastDiscovery	();