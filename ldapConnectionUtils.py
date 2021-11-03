from ldap3 import IP_V4_ONLY
import ldap3
def return_ldap3_connection_object(LDAPSU,LDAPSP,LDAPHOSTS,ENABLE_GLOBAL_CATALOG):
    HOSTS = LDAPHOSTS.split(",")
    if (ENABLE_GLOBAL_CATALOG):
        if len(HOSTS) == 1:
            return ldap3.Connection(ldap3.Server(HOSTS[0], port=3269, use_ssl=True, get_info=None, mode=IP_V4_ONLY), auto_bind=True, user=LDAPSU, password=LDAPSP, read_only=True, auto_range=True)
        else:
            for host in HOSTS:
                try:
                    return ldap3.Connection(ldap3.Server(host, port=3269, use_ssl=True, get_info=None, mode=IP_V4_ONLY), auto_bind=True, user=LDAPSU, password=LDAPSP, read_only=True, auto_range=True)
                except:
                    continue
    else:
        if len(HOSTS) == 1:
            return ldap3.Connection(ldap3.Server(HOSTS[0], port=636, use_ssl=True, get_info=None, mode=IP_V4_ONLY), auto_bind=True, user=LDAPSU, password=LDAPSP, read_only=True, auto_range=True)
        else:
            for host in HOSTS:
                try:
                    return ldap3.Connection(ldap3.Server(host, port=636, use_ssl=True, get_info=None, mode=IP_V4_ONLY), auto_bind=True, user=LDAPSU, password=LDAPSP, read_only=True, auto_range=True)
                except:
                    continue