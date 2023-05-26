#!/usr/bin/env python3
# Sniff what sending services are registered on a domain
import argparse
from SPF2IP import SPF2IP


# String match on known domains
def well_known(value):
    known_list = {
        'google.com': 'Google',
        'zendesk.com': 'Zendesk',
        'mcsv.net': 'MailChimp',
        'hostedemail.com': 'uk2.net',
        'mandrillapp.com': 'Mandrill',
        'mailgun.org': 'Mailgun',
        'stspg-customer.com': 'Atlassian Status Page',
        'sendgrid.net': 'Sendgrid',
        'mktomail.com': 'Marketo',
        'hubspotemail.net': 'HubSpot',
    }
    for k, v in known_list.items():
        if value.endswith(k):
            return v


def sniff(domain:str):
    q = SPF2IP(domain)
    res = q.DomainIPs()
    for k, v in res.items():
        chk = well_known(k)
        if chk:
            print(chk) # Just give short-form output for known ESPs
        else:
            print(k)
            for ipVer in v: # iterate over ipv4 and ipv6 results
                print('  {}'.format(ipVer))
                for ip in v[ipVer]:
                    print('    {:20} PTR:{}'.format(ip, q.ReverseIP(ip)))

# -----------------------------------------------------------------------------------------
# Main code
# -----------------------------------------------------------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description='Simple command-line tool to follow SPF records on the specified domain')
    p.add_argument('domain', nargs='+', help='domains to search for SPF records on')
    args = p.parse_args()
    for d in args.domain:
        sniff(d)