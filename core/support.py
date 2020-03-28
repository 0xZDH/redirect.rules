#!/usr/bin/env python3

## RewriteEngine rewrite rules and conditions
REWRITE = {
    'COND_IP':    '\tRewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'{IP}\'"\t[OR]\n',
    'COND_HOST':  '\tRewriteCond\t\t\t\t%{{HTTP_HOST}}\t\t\t\t\t{HOSTNAME}\t[OR,NC]\n',
    'COND_AGENT': '\tRewriteCond\t\t\t\t%{{HTTP_USER_AGENT}}\t\t\t\t\t{AGENT}\t[OR,NC]\n',
    'END_COND':   '\tRewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'192.168.250.250\'"\n',
    'RULE':       '\tRewriteRule\t\t\t\t^.*$\t\t\t\t\t%{REQUEST_SCHEME}://${REDIR_TARGET}\t[L,R=302]\n'
}

def print_exclude_list():
    print('[+] Exclusion List:')
    print('    --------------')

    print('\n\tExclude all dynamic sources:')
    print('\t\t`dynamic`')
    print('\tExclude all static sources:')
    print('\t\t`static`')

    print('\n\tStatic Sources:')
    print('\t--------------')
    print('\tExclude User-Agents:')
    print('\t\t`agents`, `user-agents`')
    print('\tExclude data via Malware Kit:')
    print('\t\t`mk`, `malware`, `malwarekit`')
    print('\tExclude ASN via RADB:')
    print('\t\t`radb`, `asnradb`')
    print('\tExclude ASN via BGPView:')
    print('\t\t`bgpview`, `asnbgpview`')
    print('\tExclude Miscelenaeous:')
    print('\t\t`misc`')

    print('\n\tDynamic Sources:')
    print('\t---------------')
    print('\tExclude curi0usJack .htaccess:')
    print('\t\t`jack`, `htaccess`, `curiousjack`')
    print('\tExclude Tor Exit Nodes:')
    print('\t\t`tor`')
    print('\tExclude AWS:')
    print('\t\t`aws`')
    print('\tExclude Google Cloud:')
    print('\t\t`google`, `googlecloud`')
    print('\tExclude Microsoft Azure:')
    print('\t\t`azure`')
    print('\tExclude Office 365:')
    print('\t\t`o365`, `office`, `office365`')
    print('\tExclude Oracle Cloud:')
    print('\t\t`oracle`, `oraclecloud`')