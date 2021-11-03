from excelUtils import *
from ldapConnectionUtils import return_ldap3_connection_object
from generalUtils import *
from getpass import getpass
from ldap3.utils.conv import escape_filter_chars
from sys import exit

import threading
import time
import os
import datetime
import ast
import sys
import io
import openpyxl
import argparse
import ldap3

ldap3.utils.config._IGNORE_MALFORMED_SCHEMA = True



# Parser to grab arguments from the user.
parser = argparse.ArgumentParser()
parser.add_argument("-U", "-u", "--USER", type=str, help="LDAP Bind Username.....ex. --USER DOMAIN\\user", required=True)
parser.add_argument("-D", "-d", "--DOMAINS", type=str, nargs='?', help="CSV of domains to search through...ex --D local.domain,domain.local",required=True)
parser.add_argument("-V", "-v", "--VERBOSE", default=False, const=True, type=str, nargs='?', help="Output additional detail",required=False)
parser.add_argument("-YES_RECOVERY", "-RECOVERY", "--RECOVERY", default=False, const=True, type=str, nargs='?', help="Output additional detail",required=False)
parser.add_argument("-NO_RECOVERY", "-NORECOVERY", "--NORECOVERY", default=False, const=True, type=str, nargs='?', help="Output additional detail",required=False)
parser.add_argument("-HOSTS", "-hosts", "--LDAPHOSTS", type=str, nargs='?', help="CSV of LDAP servers to query...ex. --LDAPHOSTS addc.domain.local,gcserver.local,10.10.10.10",required=True)
parser.add_argument("-QUERY", "-SEARCH", "-query","-search","--SEARCHQUERY", default=False, const=True, type=str, nargs='?', help="String to filter AD groups, only groups that contain the specified query will be processed...ex. --SEARCHQUERY *VPN*",required=True)
parser.add_argument("-T", "-t", "--NUMTHREADS", default=1, const=True, type=int, nargs='?', help="Defines the number of threads to use to analyze AD groups, default is 4.",required=False)

CLI_ARGS = parser.parse_args()

couldnt_find_objectclass = []
couldnt_find_group_members = []

#Extracts OU from a DN
def retrieveSearchBases(distinguishedName_list):
    bases = set()
    for distinguishedName in distinguishedName_list:
        if type(distinguishedName) == dict:
            if 'dn' in distinguishedName.keys():
                distinguishedName = distinguishedName['dn']
            else:
                continue
        split = distinguishedName.split(",OU=")
        bases.add("OU="+split[-1])
    if len(bases) > 1: #greedy domain search to save on queries
        bases = set()
        for distinguishedName in distinguishedName_list:
            if type(distinguishedName) == dict:
                if 'dn' in distinguishedName.keys():
                    distinguishedName = distinguishedName['dn']
                else:
                    continue
            bases.add(returnDomain(distinguishedName))
    return bases

#Interacts with the Directory for Group Information, returns an LDAP3.Entry object.
def returnGroupEntryV2(domains,OU,local_ldap3_connection_object,SEARCHQUERY):
    results = []
    for domain in domains:
        ldap_searchbase_filter = "OU={},{}".format(OU,domain)
        attrs = ['member']
        ldap_search_filter = "(&(objectClass=group)(cn={})(!(groupType=2)))".format(SEARCHQUERY)
        local_ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
        results += local_ldap3_connection_object.response
    return results

#Returns what objectClass a given DN is 
def checkDNObjectClassTypeGroupSearch(distinguishedName_list, ldap_searchbase_filter_list, ldap3_connection_object, ldap3_gc_connection_object, searchquery_DN_result):
    total_entries_for_group_search = []
    attrs = ['objectClass']
    if type(ldap_searchbase_filter_list) == list:
        for ldap_searchbase_filter in ldap_searchbase_filter_list:
            if len(distinguishedName_list) == 1:
                ldap_search_filter = "(distinguishedName={})".format(escape_filter_chars(distinguishedName_list[0]))
            else:
                ldap_filter_concat_string = ""
                for distinguishedName in distinguishedName_list:
                    ldap_filter_concat_string += "(distinguishedName={})".format(escape_filter_chars(distinguishedName))
                ldap_search_filter = "(|{})".format(ldap_filter_concat_string)
            try:
                ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
            except ldap3.core.exceptions.LDAPInvalidFilterError:
                print("[-] {} Thread {} Couldnt get any LDAP search results...trying to escapefilter entire string for distinguishedName \n  {}\n)".format(currT(),threading.current_thread().name,distinguishedName,distinguishedName_list),end="")
                ldap_search_filter = escape_filter_chars(ldap_search_filter)
                try:
                    ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
                except:
                    print("[-] {} Thread {} Couldnt get any LDAP search results...second search attempt failed for distinguishedName \n  {}\n)".format(currT(),threading.current_thread().name,distinguishedName,distinguishedName_list),end="")
            except ldap3.core.exceptions.LDAPInvalidDnError:
                print(ldap_search_filter)
                b=1
            if len(ldap3_connection_object.entries) > 0:
                total_entries_for_group_search += ldap3_connection_object.response
            else:
                try:
                    ldap3_gc_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
                except ldap3.core.exceptions.LDAPInvalidFilterError:
                    error=1 #fall to else to report error
                if len(ldap3_gc_connection_object.entries) > 0:
                    total_entries_for_group_search += ldap3_gc_connection_object.response
                else:
                    print("[-] {} Thread {} Could not find object class for distinguishedName {}\n".format(currT(),threading.current_thread().name,distinguishedName),end="")
                    couldnt_find_objectclass.append({searchquery_DN_result:distinguishedName})
                    return []
    else:
        ldap_searchbase_filter = ldap_searchbase_filter_list
        if len(distinguishedName_list) == 1:
            data = distinguishedName_list[0]
            if type(data) == dict:
                ldap_search_filter = "(distinguishedName={})".format(escape_filter_chars(data['dn']))
            else:
                ldap_search_filter = "(distinguishedName={})".format(escape_filter_chars(data))
        else:
            ldap_filter_concat_string = ""
            for distinguishedName in distinguishedName_list:
                if type(distinguishedName) == dict:
                    if 'dn' not in list(distinguishedName_list.keys()):
                        continue
                    distinguishedName = distinguishedName ['dn']
                ldap_filter_concat_string += "(distinguishedName={})".format(escape_filter_chars(distinguishedName))
            ldap_search_filter = "(|{})".format(ldap_filter_concat_string)
        try:
            ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
        except ldap3.core.exceptions.LDAPInvalidFilterError:
            print("[-] {} Thread {} Couldnt get any LDAP search results...trying to escapefilter entire string for distinguishedName \n  {}\n)".format(currT(),threading.current_thread().name,distinguishedName,distinguishedName_list),end="")
            ldap_search_filter = escape_filter_chars(ldap_search_filter)
            try:
                ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
            except:
                print("[-] {} Thread {} Couldnt get any LDAP search results...second search attempt failed for distinguishedName \n  {}\n)".format(currT(),threading.current_thread().name,distinguishedName,distinguishedName_list),end="")
        except ldap3.core.exceptions.LDAPInvalidDnError:
            print(ldap_search_filter)
            b=1
        if len(ldap3_connection_object.entries) > 0:
            total_entries_for_group_search += ldap3_connection_object.response
        else:
            try:
                ldap3_gc_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
            except ldap3.core.exceptions.LDAPInvalidFilterError:
                error=1
                #fall to else to report error
            if len(ldap3_gc_connection_object.entries) > 0:
                total_entries_for_group_search += ldap3_gc_connection_object.response
            else:
                print("[-] {} Thread {} Could not find object class for distinguishedName {}\n".format(currT(),threading.current_thread().name,distinguishedName),end="")
                couldnt_find_objectclass.append({searchquery_DN_result:distinguishedName})
                return []
    return total_entries_for_group_search

#Pull the members of a provided groupDN, return those values if any.
def checkGroupDNMembers(distinguishedName, ldap_searchbase_filter, ldap3_connection_object, ldap3_gc_connection_object):
    dn = escape_filter_chars(distinguishedName)
    attrs = ['member']
    ldap_search_filter = "(&(objectClass=group)(distinguishedName={}))".format(distinguishedName)
    ldap3_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)

    if len(ldap3_connection_object.entries) > 0:
        return ldap3_connection_object.response

    else:
        ldap3_gc_connection_object.search(ldap_searchbase_filter, ldap_search_filter, attributes=attrs)
        if len(ldap3_gc_connection_object.entries) > 0:
            return ldap3_gc_connection_object.response
        else:
            print("[-] {} Thread {} could not find group-member list for distinguishedName {}\n".format(currT(),threading.current_thread().name,dn),end="")
            couldnt_find_group_members.append(distinguishedName)
            return []
def logic_check(distinguishedName):
    a=1
    return "N/A"
    #define_logic

#Return number of members of the current DN, does not consider members in sub-groups.
def returnNumberOfImmediateMembers(distinguishedName, numMembersDS):
    return int(numMembersDS[distinguishedName])

#Retrn number of members of the current DN, including members of any any sub-groups, if any.
def returnTrueNumberOfMembers(distinguishedName, nestedGroups, numMembersDS):
    starting = returnNumberOfImmediateMembers(distinguishedName, numMembersDS)
    nestedG = nestedGroups[distinguishedName]
    if nestedG == False:
        return starting
    else:
        for g in nestedG:
            starting += returnNumberOfImmediateMembers(g, numMembersDS)
        return starting   

def returnCNValueV2(distinguishedName):
    return distinguishedName.split(",OU=")[0].split("CN=")[1]

#Extract Container from DN
def returnContainerCode(distinguishedName):
    return returnCNValueV2(distinguishedName).split("-")[0]

#Takes a list of DNs, and grabs all of their CNs for the workbook output column
def returnCNsForNestedGroupList(NestedGroupList):
    if NestedGroupList == False:
        return False
    else:
        newLst = []
        for val in NestedGroupList:
            newLst.append(returnCNValueV2(val))
        return newLst

#Returns the domain of a DN
def returnDomain(distinguishedName):
    if type(distinguishedName) == dict:
        distinguishedName = distinguishedName ['dn']
        return distinguishedName[distinguishedName.find("DC="):]
    else:
        return distinguishedName[distinguishedName.find("DC="):]

def buildOUSearchDSV2(OULIST, debug, ldap3_connection_object, ldap3_gc_connection_object, SEARCHDS, SEARCHQUERY, DOMAINS):
    OUDS = {}
    while (len(OULIST) != 0):
        OU = OULIST.pop().strip("\n")
        print("[+] {} Thread {} is beginning search for AD groups in OU {}....there are {} OUs remaining\n".format(currT(),threading.current_thread().name,OU,len(OULIST)),end="")
        OUDS.update({OU:{}})
        LDAP = []
        LDAP += returnGroupEntryV2(domains,OU,ldap3_connection_object,SEARCHQUERY)
        if len(LDAP) == 0:
            LDAP += returnGroupEntryV2(domains,OU,ldap3_gc_connection_object,SEARCHQUERY)
        if LDAP == []:
            print("[+] {} Thread {} found zero groups for OU {}\n".format(currT(),threading.current_thread().name,OU),end="")
            OUDS.update({OU:{}})
            continue
        print("[+] {} Thread {} has completed search for OU {} ... beginning analysis on {} groups ...\n".format(currT(),threading.current_thread().name,OU,len(LDAP)),end="") 
        for ldapEntryIndex in range(len(LDAP)):
            current_DN_Payload = LDAP[ldapEntryIndex]['dn']
            current_Attributes = LDAP[ldapEntryIndex]['attributes']._store
            current_Members = current_Attributes['member']
            print("[+] {} Thread {} has begun analyzing AD group DN {}\n".format(currT(),threading.current_thread().name,current_DN_Payload),end="") 
            if current_DN_Payload in OUDS[OU].keys(): 
                currentDN = current_DN_Payload 
                newMembers = current_Members
                newMembers.sort()
                OUDS[OU][currentDN].sort()
                if OUDS[OU][currentDN] == newMembers:
                    continue
                elif len(newMembers) == 0 and len(OUDS[OU][currentDN]) !=0:
                    continue
                elif len(newMembers) != 0 and len(OUDS[OU][currentDN]) ==0:
                    OUDS[OU][currentDN] = newMembers
                elif len(newMembers) == 0 and len(OUDS[OU][currentDN]) ==0:
                    continue
                else:
                    print("SEARCHDS conflict")
                    print("currentDN\n\t{}".format(currentDN))
                    print("currentDNMembers")
                    for val in OUDS[OU][currentDN]:
                        print("\t{}".format(val))
                    print("newDN\n\t{}".format(LDAP[ldapEntryIndex].distinguishedName.value))
                    print("newDNMembers")
                    for val in newMembers:
                        print("\t{}".format(val))
                    exit()
            else:
                OUDS[OU].update({current_DN_Payload:current_Members})
    SEARCHDS.update(OUDS)
    return

def gather_LDAPEntries_ObjectClassTypeGroupSearch(groupMemberOfDNs, ldap3_connection_object, ldap3_gc_connection_object, searchquery_DN_result):
    if len(groupMemberOfDNs) == 1:
        return checkDNObjectClassTypeGroupSearch(groupMemberOfDNs, returnDomain(groupMemberOfDNs[0]), ldap3_connection_object, ldap3_gc_connection_object, searchquery_DN_result)
    else:
        entries = []
        for i in range(0,len(groupMemberOfDNs),999):
            end = i+999 #Server limit for LDAP requests is 1000 entries
            entries += checkDNObjectClassTypeGroupSearch(groupMemberOfDNs[i:end], retrieveSearchBases(groupMemberOfDNs), ldap3_connection_object, ldap3_gc_connection_object, searchquery_DN_result)
        return entries

#Recursively search a group for any sub-groups.
def findRecursiveGroups(searchquery_DN_result, initSearchResultKeys, debug, ldap3_connection_object,ldap3_gc_connection_object, numMembersDS, OU):
    container_known_intel = list(SEARCHDS[OU].keys())
    currentGroupMemberCount = 0 
    nestedGroups = []
    print("[+] {} Thread {} Grabbing counts for interesting group DN {}\n".format(currT(),threading.current_thread().name,searchquery_DN_result),end="")  if debug else ""
    
    cache = False
    #We have found a group with "SEARCHQUERY" in it, we now have to see what its members consist of
        #Users add to the immediate amount
        #Groups add to the recursive total ammount
    
    
    if searchquery_DN_result in container_known_intel:
        #Check to see if we already know the members from doing Phase 1.
        groupMemberOfDNs = SEARCHDS[OU][searchquery_DN_result]
        cache = True
    else:
        #Either subgroup is missing from Phase 1 or DN didn't include search query, manually seearch again
        groupMemberOfDNs = checkGroupDNMembers(searchquery_DN_result, retrieveSearchBases([searchquery_DN_result]), ldap3_connection_object, ldap3_gc_connection_object)
        groupMemberOfDNs = groupMemberOfDNs[0]['attributes']._store
        groupMemberOfDNs = groupMemberOfDNs['member']


    if len(groupMemberOfDNs) > 0:

        #Iterates over a list of DNs to determine if they are users or groups
        objectTypeLDAPEntires = gather_LDAPEntries_ObjectClassTypeGroupSearch(groupMemberOfDNs, ldap3_connection_object, ldap3_gc_connection_object, searchquery_DN_result)


        #LDAP entry objects
        for entry in objectTypeLDAPEntires:
            if 'dn' not in list(entry.keys()):
                continue
            current_Attrib = entry['attributes']._store
            current_DName = entry['dn']

            print("[~] {} Thread {} Looking for users/recursive groups for distinguishedName {}\n".format(currT(),threading.current_thread().name,current_DName),end="")  if debug else ""
            
            if "person" in  current_Attrib['objectClass'] or "user" in current_Attrib['objectClass']:
                #Immediate user found, add one to the current group member count
                currentGroupMemberCount +=1
            else:
                time.sleep(0.1)
                print("[+] {} Thread {} Nested group discovered....beginning new recursive search for distinguishedName {}\n".format(currT(),threading.current_thread().name,current_DName),end="") 
                nestedGroups.append(current_DName)
    print("[+] {} Thread {} DONE! - confirmed {} total immediate users for distinguishedName {}\n".format(currT(),threading.current_thread().name,currentGroupMemberCount,searchquery_DN_result),end="")  if debug else ""
    numMembersDS.update({searchquery_DN_result:currentGroupMemberCount})
    if len(nestedGroups) == 0:
        return []
    elif len(nestedGroups) == 1:
        return list(set(nestedGroups + findRecursiveGroups(nestedGroups[0],initSearchResultKeys, debug, ldap3_connection_object,ldap3_gc_connection_object, numMembersDS, OU)))
    else:
        lst = []
        for i in range(len(nestedGroups)):
            lst += findRecursiveGroups(nestedGroups[i],initSearchResultKeys, debug, ldap3_connection_object,ldap3_gc_connection_object, numMembersDS, OU)
        return list(set(nestedGroups + lst))

#Processes an entire OU for recursive groups. This also allows the program to work with parallelism.
def processOUForRecursiveGroups(OULIST, nestedGroups, numMembersDS, SEARCHDS, debug, ldap3_connection_object,ldap3_gc_connection_object):
    while (len(OULIST) != 0):
        OU = OULIST.pop().strip("\n")
        print("[~] {} Thread {} working on RECURSIVEDS in OU {}....there are {} OUs remaining\n".format(currT(),threading.current_thread().name,OU,len(OULIST)),end="")
        try:
            initSearchResultKeys = list(SEARCHDS[OU].keys())
            if len(initSearchResultKeys) > 0:
                for groupDN in initSearchResultKeys:
                    if groupDN not in nestedGroups.keys():
                        time.sleep(0.1)
                        nestedGroupList = findRecursiveGroups(groupDN,initSearchResultKeys, debug, ldap3_connection_object,ldap3_gc_connection_object, numMembersDS, OU)
                        if nestedGroupList != []:
                            nestedGroups.update({groupDN:nestedGroupList})
                        else:
                            nestedGroups.update({groupDN:False})
            else:
                #no work to do, this OU didnt have any interesting groups come back.
                writeToDisk("group_count_cache.txt",nestedGroups)
                writeToDisk("group_member_counts.txt",numMembersDS)
        except Exception as e:
            try:
                del nestedGroups[groupDN]
                del numMembersDS[groupDN]
            except:
                a=1
            OULIST.add(OU)
            beep()
            writeToDisk("group_count_cache.txt",nestedGroups)
            writeToDisk("group_member_counts.txt",numMembersDS)
            beep()
            print("[-] {} Thread {} ERROR: {} while working on OU {}\n".format(currT(),threading.current_thread().name,e, OU),end="")
            exit()

def export_data():
    #Export data to workbook
    whatCNsAreSubGroups = []

    #### FIX ISSUBGROUPCODE#########
    for OU in SEARCHDS.keys():
        initSearchResultKeys = list(SEARCHDS[OU].keys())
        initSearchResultKeys.sort()
        for k in initSearchResultKeys:
            nestedGroupCNList = returnCNsForNestedGroupList(nestedGroups[k])
            if nestedGroupCNList != False:
                whatCNsAreSubGroups += nestedGroupCNList
    whatCNsAreSubGroups.sort()
    wb = generateWorkBook()
    resultSheet = wb["RESULTS"]
    startingRowNum = 2
    for OU in SEARCHDS.keys():
        initSearchResultKeys = list(SEARCHDS[OU].keys())
        initSearchResultKeys.sort()
        for k in initSearchResultKeys:
            currentCNVal = returnCNValueV2(k)

            if currentCNVal in whatCNsAreSubGroups:
                isSubGroup = True
            else:
                isSubGroup = False

            nestedGroupCNList = returnCNsForNestedGroupList(nestedGroups[k])

            if nestedGroupCNList == False:
                hasSubGroups = False
            else:
                hasSubGroups = True

            Rowoutput = [currentCNVal, #CN
                    returnContainerCode(k), #container Code
                    returnTrueNumberOfMembers(k, nestedGroups, numMembersDS), #Recursive Num Members
                    returnNumberOfImmediateMembers(k, numMembersDS),  #Group Num Members
                    logic_check(k), #Custom Group Check
                    returnDomain(k), #Domain 
                    isSubGroup, #Is the CN a subgroup else where?
                    hasSubGroups, #Does the CN have subgroups?
                    k, #DN
                    str(nestedGroupCNList).replace(", ", ",").replace("[", "").replace("]", "").replace("'", ""), #Subgroup CSV
                    ]
            writeToWB(resultSheet,startingRowNum,Rowoutput)
            startingRowNum +=1
    wb.save("ADREPORT.xlsx")

def domain_string_generator(domains_csv):
    results = set()
    lst = domains_csv.split(',')
    for d in lst:
        d_lst = d.split(".")
        results.add("DC={},DC={}".format(d_lst[0],d_lst[1]))
    return list(results)

if __name__ == "__main__": 
    start = currT()
    debug = CLI_ARGS.VERBOSE
    recovery = CLI_ARGS.RECOVERY
    no_recovery = CLI_ARGS.NORECOVERY
    domains = domain_string_generator(CLI_ARGS.DOMAINS)
    domains.sort()
    LDAPSP = getpass("[?] {} Enter Bind Password For {}\nPassword: ".format(currT(),CLI_ARGS.USER))
    #Build LDAPS bind object
    try:
        print("[~] {} Attempting login....".format(currT()))
        ldap3_connection_object = return_ldap3_connection_object(CLI_ARGS.USER,LDAPSP,CLI_ARGS.LDAPHOSTS,False)
        ldap3_gc_connection_object = return_ldap3_connection_object(CLI_ARGS.USER,LDAPSP,CLI_ARGS.LDAPHOSTS,True)
    except:
        print("\n\n[-] {} Either wrong password or cant connect to LDAPS/GC. Please restart the program and try again...".format(currT()))
        exit()

    if (ldap3_connection_object == None) or (ldap3_gc_connection_object == None):
        print("\n\n[-] {} Either wrong password or cant connect to LDAPS/GC. Please restart the program and try again...".format(currT()))
        exit()

    #Delete Credentials from Memory
    del LDAPSP

    print("[+] {} Login successful...parsing OU temp_user_input file for AD organizational units".format(currT()))
    OUs = open("OUs.txt", "r").readlines()

    popList = set(OUs)

    #Crash handling
    current_working_directory_file_list = os.listdir()
    user_answer_1 = False
    user_answer_2 = False
    ANS3 = False
    numThreads = CLI_ARGS.NUMTHREADS
    #threadIterator = BreakOUsForThreads(numThreads,OUs)


    if "search_results_cache.txt" in current_working_directory_file_list:
        temp_user_input = input("[?] {} You have a Phase 1 snapshot, do you want to use this during program init? (SEARCH RESULTS CACHE) [y\\n]: ".format(currT()))
        if temp_user_input == "y" or temp_user_input == "Y":
            user_answer_2 = True

    if "group_count_cache.txt" in current_working_directory_file_list or "group_count_cache.txt" in current_working_directory_file_list:
        temp_user_input = input("[?] {} You have a Phase 2 snapshot, do you want to use this during program init? (GROUP COUNT CACHE) [y\\n]: ".format(currT()))
        if temp_user_input == "y" or temp_user_input == "Y":
            user_answer_1 = True

    


    if "group_count_cache.txt" in current_working_directory_file_list and user_answer_1:
        infile = open("group_count_cache.txt",'r').read()
        nestedGroups = ast.literal_eval(infile)
    else:
        nestedGroups = {}

    if "group_member_counts.txt" in current_working_directory_file_list and user_answer_2:
        infile = open("group_member_counts.txt",'r').read()
        numMembersDS = ast.literal_eval(infile)
    else:
        numMembersDS = {}

    #crashHandling

    if "search_results_cache.txt" in current_working_directory_file_list and user_answer_2:
        with io.open("search_results_cache.txt", 'r', encoding="utf-8") as f:  
            infile = f.read()
        SEARCHDS = ast.literal_eval(infile)
    else:
        print("[P1] {} Now beginning phase 1....gathering AD groups that contain '{}' to build the SEARCHDS\n".format(currT(),CLI_ARGS.SEARCHQUERY),end="") 
        SEARCHDS = {} #Dictionary of OUs imported in OUs.txt
        for OU in OUs:
            SEARCHDS.update({OU.strip("\n"):{}})
        try:
            # creating thread
            threadList = []
            #for OUContainerIndex in range(len(threadIterator)):
            for num in range(numThreads):
                threadList.append(threading.Thread(target=buildOUSearchDSV2, args=(popList, debug, ldap3_connection_object, ldap3_gc_connection_object, SEARCHDS, CLI_ARGS.SEARCHQUERY, domains), name="t{}".format(num)))
            for t in threadList:
                t.start()
                time.sleep(0.1)
            for t in threadList:
                t.join()    
        except Exception as e:
            print(e)
            beep()
            writeToDisk("search_results_cache.txt",SEARCHDS) #cache to speed up processing for next run
            beep()
            exit()
        writeToDisk("search_results_cache.txt",SEARCHDS) #cache to speed up processing for next run

    firstHalf = currT()

    def remove_empty_OUs():
        organizational_units = list(SEARCHDS.keys())
        for unit in organizational_units:
            unit_size = len(SEARCHDS[unit])
            if unit_size == 0:
                del SEARCHDS[unit]

    remove_empty_OUs()

    print("[P2] {} Now beginning phase 2....gathering AD group membership and analyizing quantities for groups collected in [P1]...\n".format(currT(),CLI_ARGS.SEARCHQUERY),end="") 

    popList = set(SEARCHDS.keys())

    threadList = []

    for num in range(numThreads):
        threadList.append(threading.Thread(target=processOUForRecursiveGroups, args=(popList,nestedGroups,numMembersDS,SEARCHDS,debug,ldap3_connection_object,ldap3_gc_connection_object), name="t{}".format(num)))
    for t in threadList:
        t.start()
    for t in threadList:
        t.join()    

    writeToDisk("group_count_cache.txt",nestedGroups)
    writeToDisk("group_member_counts.txt",numMembersDS)


export_data()
beep()
print("FirstHalf:")
end(firstHalf)
print()
end(start)

writeToDisk("couldnt_find_objectclass.txt",couldnt_find_objectclass)
writeToDisk("couldnt_find_group_members.txt",couldnt_find_group_members)
    
