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

    print('\n\tThis list represents the value(s) a user can pass to the `--exclude` argument in order')
    print('\tto exclude a specific data source from being added to the final redirect.rules file.')
    print('\tNOTE: The `--exclude` argument accepts keywords and/or specific IP/Host/User-Agent\'s')
    print('\tto be excluded delimited by: SPACE')

    print('\n\tExample usage of the `--exclude` argument:')
    print('\t\t--exclude user-agents radb 35.0.0.0/8')

    print('\n\tExclusion Keyword List:')
    print('\t----------------------')
    print('\t\tdynamic\t\t# Exclude all dynamic sources')
    print('\t\tstatic\t\t# Exclude all static sources')
    print('\t\thtaccess\t# Exclude @curi0usJack\'s .htaccess file')
    print('\t\tuser-agents')
    print('\t\tmalwarekit')
    print('\t\tradb\t\t# Exclude ASN data from RADB')
    print('\t\tbgpview\t\t# Exclude ASN data from BGPView')
    print('\t\tAS#\t\t# Exclude a specific ASN based on AS# format')
    print('\t\tmisc')
    print('\t\ttor')
    print('\t\taws')
    print('\t\tgooglecloud')
    print('\t\tmicrosoft')
    print('\t\tazure')
    print('\t\toffice365')
    print('\t\toraclecloud')

    print('\n\tNOTE: Company names/identifiers used within the core/data/asns.py')
    print('\tfile can also be used.')
    print('\tExclude All ZScaler ASN\'s: `--exclude ZSCALER`')
    print('\tExclude ZScaler\'s ATL ASN: `--exclude ZSCALER-ATLANTA`')