import win32net, win32wnet, win32security, win32com.client, win32netcon

#Returns the list of local users to a system 
def get_users(host):
    ad_user_list = []
    resume = 0
    while 1:
        (_users, total, resume) = win32net.NetUserEnum(host,3,win32netcon.FILTER_NORMAL_ACCOUNT,
                                                 resume,win32netcon.MAX_PREFERRED_LENGTH)
        for _user in _users:
            ad_user_list.append(_user['name'])
        return ad_user_list
    if not resume:
        return ad_user_list

#Local group list on a host (including DC's) format {host:[group]}
def get_groups(host):
    ad_group_list = []
    resume = 0
    while 1:
        (_groups, total, resume) = win32net.NetLocalGroupEnum(host,0,resume,win32netcon.MAX_PREFERRED_LENGTH)
        for _group in _groups:
            ad_group_list.append(_group['name'])
        return ad_group_list
    if not resume:
        return ad_group_list
    

def is_server_type(host,type):
    try:
        if win32net.NetServerGetInfo(host,102)['type'] & type == type:
            return True
        else:
            return False
    except:
        pass
        

def server_type(host):
    try:
        result = win32net.NetServerGetInfo(host,102)['type']
    except:
        result = 0
    return result

def server_types(host):
    result = []
    type_list = {win32netcon.SV_TYPE_WORKSTATION:['SV_TYPE_WORKSTATION',''],
                win32netcon.SV_TYPE_SERVER:['SV_TYPE_SERVER',''],
                win32netcon.SV_TYPE_SQLSERVER:['SV_TYPE_SQLSERVER','A server running with Microsoft SQL Server.'],
                win32netcon.SV_TYPE_DOMAIN_CTRL:['SV_TYPE_DOMAIN_CTRL','A primary domain controller.'],
                win32netcon.SV_TYPE_DOMAIN_BAKCTRL:['SV_TYPE_DOMAIN_BAKCTRL','A backup domain controller.'],
                win32netcon.SV_TYPE_TIME_SOURCE:['SV_TYPE_TIME_SOURCE','A server running the Timesource service.'],
                win32netcon.SV_TYPE_AFP:['SV_TYPE_AFP','A server running the Apple Filing Protocol (AFP) file service.'],
                win32netcon.SV_TYPE_NOVELL:['SV_TYPE_NOVELL','A Novell server.'],
                win32netcon.SV_TYPE_DOMAIN_MEMBER:['SV_TYPE_DOMAIN_MEMBER','A LAN Manager 2.x domain member.'],
                win32netcon.SV_TYPE_PRINTQ_SERVER:['SV_TYPE_PRINTQ_SERVER','A server that shares a print queue.'],
                win32netcon.SV_TYPE_DIALIN_SERVER:['SV_TYPE_DIALIN_SERVER','A server that runs a dial-in service.'],
                win32netcon.SV_TYPE_XENIX_SERVER:['SV_TYPE_XENIX_SERVER','A Xenix or Unix server.'],
                win32netcon.SV_TYPE_NT:['SV_TYPE_NT','A workstation or server.'],
                win32netcon.SV_TYPE_WFW:['SV_TYPE_WFW','A computer that runs Windows for Workgroups.'],
                win32netcon.SV_TYPE_SERVER_MFPN:['SV_TYPE_SERVER_MFPN','A server that runs the Microsoft File and Print for NetWare service.'],
                win32netcon.SV_TYPE_SERVER_NT:['SV_TYPE_SERVER_NT','Any server that is not a domain controller.'],
                win32netcon.SV_TYPE_POTENTIAL_BROWSER:['SV_TYPE_POTENTIAL_BROWSER','A computer that can run the browser service.'],
                win32netcon.SV_TYPE_BACKUP_BROWSER:['SV_TYPE_BACKUP_BROWSER','A server running a browser service as backup.'],
                win32netcon.SV_TYPE_MASTER_BROWSER:['SV_TYPE_MASTER_BROWSER','A server running the master browser service.'],
                win32netcon.SV_TYPE_DOMAIN_MASTER:['SV_TYPE_DOMAIN_MASTER','A server running the domain master browser.'],
                win32netcon.SV_TYPE_SERVER_OSF:['SV_TYPE_SERVER_OSF','A computer that runs OSF.'],
                win32netcon.SV_TYPE_SERVER_VMS:['SV_TYPE_SERVER_VMS','A computer that runs VMS.'],
                win32netcon.SV_TYPE_WINDOWS:['SV_TYPE_WINDOWS','A computer that runs Windows.'],
                win32netcon.SV_TYPE_DFS:['SV_TYPE_DFS','A server that is the root of a DFS tree.'],
                win32netcon.SV_TYPE_CLUSTER_NT:['SV_TYPE_CLUSTER_NT','A server cluster available in the domain.'],
                win32netcon.SV_TYPE_DCE:['SV_TYPE_DCE','A server that runs the DCE Directory and Security Services or equivalent.'],
                win32netcon.SV_TYPE_ALTERNATE_XPORT:['SV_TYPE_ALTERNATE_XPORT','A server that is returned by an alternate transport.'],
                win32netcon.SV_TYPE_LOCAL_LIST_ONLY:['SV_TYPE_LOCAL_LIST_ONLY','A server that is maintained by the browser.'],
                win32netcon.SV_TYPE_DOMAIN_ENUM:['SV_TYPE_DOMAIN_ENUM','A primary domain.']}
    for t in type_list:
        if server_type(host) & t == t:
            result.append(type_list[t][0])
    return result

#stores the hosts reachable on the current domain into a variable
#This is different than checking AD, as it will only return the active nodes
def get_hosts():
    #list of all hosts except
    server_list = []
    workstation_list = []
    dc_list = []
    all_hosts = []
    _hosts = win32net.NetServerEnum(None,100)
    for _host in _hosts[0]:
        if is_server_type(_host['name'],win32netcon.SV_TYPE_DOMAIN_CTRL):
            dc_list.append(_host['name'])
        elif (is_server_type(_host['name'],win32netcon.SV_TYPE_SQLSERVER)) or (is_server_type(_host['name'],win32netcon.SV_TYPE_SERVER_NT)):
            server_list.append(_host['name'])
        else:
            workstation_list.append(_host['name'])
        all_hosts.append(_host['name'])
    return server_list,dc_list,workstation_list,all_hosts


#dc = win32security.DsGetDcName(None, None)
#domain = dc['DomainName']
#server = dc['DomainControllerName']
#Handle = win32security.DsBind(server,domain)
#hosts_list = get_hosts()
#results = {}
#for host in hosts_list:
#    if host == dc:

#separate live systems by type
(servers,dc,workstations,live_hosts) = get_hosts()

#Structure of hosts_groups {host:[group...group]}
hosts_groups = {}
#Structure of hosts_users {host:[user...user]}
hosts_users = {}
for h in (workstations+servers):
        hosts_groups[h] = get_groups(h) #list of local groups, except dc, as this returns domain/global groups
        hosts_users[h] = get_users(h)   #list of local users


#for h in hosts_groups:
#    for g in hosts_groups[h]:
#        print(h,u,win32net.NetUserGetLocalGroups(h,u))

# Procedure to return a list of members for a given group
def get_group_members(host,group):
    group_members = []
    resume = 0
    while 1:
        (_members, total, resume) = win32net.NetLocalGroupGetMembers(host,group,3,resume,win32netcon.MAX_PREFERRED_LENGTH)
        for _member in _members:
            group_members.append(_member['domainandname'])
        return group_members
    if not resume:
        return group_members

group_members = {}

#Structure of group_members {host:{group:[user...user]}} again only on servers that are NOT DC's
#for h in (workstations+servers):
#    for g in hosts_groups[h]:
#        group_members[g] = get_group_members(h,g)
#print(group_members)
#print(group_members)
#computer_search_base = "CN=Computers,"+domainDN
#group_user_search_base = "CN=Users,"+domainDN

#subobj={}

#for o in rootobj:
#    temp = adsi.GetObject("",o + ',' + domainDN)
#    for a in temp:
#        subobj[a]=a.name
        
#print(subobj)   

