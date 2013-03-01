#include <stdio.h>
#include <iptables.h>

static void SYNPROXY_help(void)
{
	printf(
"SYNPROXY target options:\n"
"no options\n");
}

static struct xtables_target reject_tg_reg = {
	.name		= "SYNPROXY",
	.version	= XTABLES_VERSION,
	.family		= PF_INET,
	.help		= SYNPROXY_help,
};

void _init(void)
{
	xtables_register_target(&reject_tg_reg);
}
