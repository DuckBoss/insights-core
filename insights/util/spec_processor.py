import logging
import os
import re
import six
import socket
import struct

from tempfile import TemporaryFile

logger = logging.getLogger(__name__)

# The regex for password removal, which is read from the "/etc/insights-client/.exp.sed"
default_password_regexs = [
    "(password[a-zA-Z0-9_]*)(\s*\:\s*\"*\s*|\s*\"*\s*=\s*\"\s*|\s*=+\s*|\s*--md5+\s*|\s*)([a-zA-Z0-9_!@#$%^&*()+=/-]*)",
    "(password[a-zA-Z0-9_]*)(\s*\*+\s+)(.+)",
]


class PostProcessor(object):
    def __init__(self, config, rm_conf, fqdn='localhost.example.com'):
        # Obfuscation - set: ip and hostname only
        self.obfuscate = set()
        self.obfuscate.add('ip') if config.obfuscate else None
        self.obfuscate.add('hostname') if config.obfuscate_hostname else None

        # Redaction - dict:
        rm_conf = rm_conf or {}
        exclude = rm_conf.get('patterns', [])
        regex = False
        if isinstance(exclude, dict) and exclude.get('regex'):
            exclude = [r'%s' % i for i in exclude['regex']]
            regex = True
        self.redact = dict(
            exclude=exclude,
            regex=regex,
            commands=rm_conf.get('commands', []),
            files=rm_conf.get('files', []))

        # hostname of the current host
        name_list = fqdn.split('.')
        self.hostname = name_list[0]
        self.fqdn = fqdn
        self.domain = None if len(name_list) <= 1 else '.'.join(name_list[1:])

        # IP obfuscate information
        self.ip_db = dict()  # IP database
        self.start_ip = '10.230.230.1'

        # Hostname obfuscate information
        self.hn_db = dict()  # hostname database
        self.hostname_count = 0
        self.hashed_fqdn = None   # addition for insights-client

        # Domain name obfuscate information
        self.dn_db = dict()  # domain name database
        self.domain_count = 0

        # Keyword obfuscate information
        keywords = rm_conf.get('keywords')
        self.kw_db = dict()  # keyword database
        self.kw_count = 0
        if self.obfuscate and keywords:
            logger.warning("Will Skip keywords defined in blacklist configuration")
            self._keywords2db(keywords)

        if config.obfuscate_hostname and self.fqdn:
            self._domains2db()
            self.hashed_fqdn = self._sub_hostname(self.fqdn)

    def _sub_ip(self, line):
        '''
        This will substitute an obfuscated IP for each instance of a given IP in a file
        This is called in the self._clean_line function, along with user _sub_* functions to scrub a given
        line in a file.
        It scans a given line and if an IP exists, it obfuscates the IP using _ip2db and returns the altered line
        '''
        try:
            pattern = r"(((\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[1-9]))(\.(\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[0-9])){3})"
            ips = [each[0] for each in re.findall(pattern, line)]
            if ips:
                for ip in sorted(ips, key=len, reverse=True):
                    # skip loopback (https://github.com/RedHatInsights/insights-core/issues/3230#issuecomment-924859845)
                    if ip != "127.0.0.1" and ip in line:
                        new_ip = self._ip2db(ip)
                        logger.debug("Obfuscating IP - %s > %s", ip, new_ip)
                        line = line.replace(ip, new_ip)
            return line
        except Exception:  # pragma: no cover
            raise Exception('SubIPError: Unable to Substitute IP Address - %s', ip)

    def _sub_ip_netstat(self, line):
        '''
        Special version of _sub_ip for netstat to preserve spacing
        '''
        try:
            pattern = r"(((\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[1-9]))(\.(\b25[0-5]|\b2[0-4][0-9]|\b1[0-9][0-9]|\b[1-9][0-9]|\b[0-9])){3})"
            ips = [each[0] for each in re.findall(pattern, line)]
            if ips:
                for ip in sorted(ips, key=len, reverse=True):
                    # skip loopback (https://github.com/RedHatInsights/insights-core/issues/3230#issuecomment-924859845)
                    if ip != "127.0.0.1" and ip in line:
                        ip_len = len(ip)
                        new_ip = self._ip2db(ip)
                        new_ip_len = len(new_ip)
                        logger.debug("Obfuscating IP - %s > %s", ip, new_ip)
                        # pad or remove spaces to allow for the new length
                        if ip_len > new_ip_len:
                            numspaces = ip_len - new_ip_len
                            line = line.replace(ip, new_ip)

                            # shift past port specification to add spaces
                            idx = line.index(new_ip) + new_ip_len
                            c = line[idx]
                            while c != " ":
                                idx += 1
                                if idx == len(line):
                                    idx = len(line) - 1
                                    break
                                c = line[idx]
                            line = line[0:idx] + numspaces * " " + line[idx:]

                        elif new_ip_len > ip_len:
                            numspaces = new_ip_len - ip_len
                            line = line.replace(ip, new_ip)

                            # shift past port specification to skip spaces
                            idx = line.index(new_ip) + new_ip_len
                            c = line[idx]
                            while c != " ":
                                idx += 1
                                if idx == len(line):
                                    break
                                c = line[idx]
                            line = line[0:idx] + line[(idx + numspaces):]

                        else:
                            line = line.replace(ip, new_ip)
            return line
        except Exception:  # pragma: no cover
            raise Exception('SubIPError: Unable to Substitute IP Address - %s', ip)

    ########################
    #   Domain Functions   #
    ########################

    def _dn2db(self, domain, add_domain=False):
        """Adds a domain to dn_db and returns the obfuscated value."""
        try:
            o_domain = self.dn_db.get(domain)
            if o_domain is None:
                # Try converting it all to lowercase
                if add_domain:
                    self.domain_count += 1
                    o_domain = "domain%s.com" % self.domain_count
                    self.dn_db[domain] = o_domain
                    logger.debug("Adding new obfuscated domain - %s > %s", domain, o_domain)

            if o_domain:
                return o_domain
            else:
                return None

        except Exception as e:  # pragma: no cover
            logger.exception(e)
            raise Exception("DN2DB_ERROR: Unable to retrieve obfuscated domain - %s", domain)

    def _domains2db(self):
        """Adds domains to the domain database"""
        try:
            if self.domain is not None:
                self._dn2db(self.domain, add_domain=True)

        except Exception as e:  # pragma: no cover
            logger.exception(e)
            raise Exception("DOMAINS2DB_ERROR: Unable to process domains")

    def _validate_domainname(self, hostname):
        domainname = hostname.split('.')
        domain_depth = len(domainname)
        logger.debug("validating domain %s - depth: %s", hostname, domain_depth)
        found_domain = False
        if domain_depth > 2:
            # everything after the hostname is the domain we need to check
            root_domain = '.'.join(domainname[1:domain_depth])
            o_domain = self._dn2db(root_domain)
            found_domain = True
            if o_domain is None:
                logger.debug("Found new subdomain of %s - %s", root_domain, domainname)
                o_domain = self._dn2db(root_domain, add_domain=True)
            else:
                logger.debug("Found domain in domain database - %s", o_domain)
        elif domain_depth == 2:
            o_domain = self.dn_db.get(hostname)
            if o_domain:
                logger.debug("Domain found in domain database - %s", domainname)
                found_domain = True

        return found_domain

    ###########################
    #   Hostname functions    #
    ###########################

    def _hn2db(self, host):
        try:
            o_host = self.hn_db.get(host)
            if o_host is None:  # no database match
                split_host = host.split('.')
                self.hostname_count += 1  # increment the counter to get the host ID number
                if len(split_host) == 1:  # we have a non-fqdn - typically the host short name
                    o_host = "host%s" % self.hostname_count
                    self.hn_db[host] = o_host
                elif len(split_host) == 2:  # we have a root domain, a la example.com
                    o_host = self._dn2db(host)
                else:  # a 3rd level domain or higher
                    domain = '.'.join(split_host[1:])
                    o_domain = self._dn2db(domain)
                    o_host = "host%s.%s" % (self.hostname_count, o_domain)
                    self.hn_db[host] = o_host

            if o_host is not None:
                return o_host

        except Exception as e:  # pragma: no cover
            logger.exception(e)
            raise Exception("HN2DB_ERROR: Unable to add hostname to database - %s", host)

    def _sub_hostname(self, line):
        potential_hostnames = re.findall(r'\b[a-zA-Z0-9-\.]{1,200}\.[a-zA-Z]{1,63}\b', line)
        try:
            for hostname in potential_hostnames:
                hostname = hostname.lower()
                o_hostname = self.hn_db.get(hostname)
                if o_hostname:
                    line = line.replace(hostname, o_hostname)
                    logger.debug("Obfuscating hostname - %s > %s", hostname, o_hostname)
                else:
                    logger.debug("Verifying potential hostname - %s", hostname)
                    domain_found = self._validate_domainname(hostname)
                    if domain_found:
                        o_hostname = self._hn2db(hostname)
                        line = line.replace(hostname, o_hostname)
                        logger.debug("Obfuscating hostname - %s > %s", hostname, o_hostname)
            return line

        except Exception as e:  # pragma: no cover
            logger.exception(e)
            raise Exception("SUB_HOSTNAME_ERROR: Unable to obfuscate hostnames on line - %s", line)

    def _keywords2db(self, keywords):
        # processes optional keywords to add to be obfuscated
        try:
            if keywords:
                k_count = 0
                for keyword in keywords:
                    o_kw = "keyword%s" % k_count
                    self.kw_db[keyword.rstrip()] = o_kw
                    logger.debug("Added Obfuscated Keyword - %s", o_kw)
                    k_count += 1
                logger.debug("Added Keyword Contents from Customer's configuration")
                self.kw_count = k_count

        except Exception as e:  # pragma: no cover
            logger.exception(e)

    def _kw2db(self, keyword):
        return self.kw_db[keyword]

    def _sub_keywords(self, line):
        # this will substitute out any keyword entries on a given line
        if self.kw_count > 0:    # we have obfuscated keywords to work with
            for k in self.kw_db.keys():
                if k in line:
                    line = line.replace(k, self._kw2db(k))
                    logger.debug("Obfuscating Keyword - %s > %s", k, self._kw2db(k))
        return line

    def _ip2int(self, ipstr):
        # converts a dotted decimal IP address into an integer that can be incremented
        integer = struct.unpack('!I', socket.inet_aton(ipstr))[0]

        return integer

    def int2ip(self, num):
        # converts an integer stored in the IP database into a dotted decimal IP
        ip = socket.inet_ntoa(struct.pack('!I', num))

        return ip

    def _ip2db(self, ip):
        '''
        adds an IP address to the IP database and returns the obfuscated entry, or returns the
        existing obfuscated IP entry
        FORMAT:
        {$obfuscated_ip: $original_ip,}
        '''

        ip_num = self._ip2int(ip)
        ip_found = False
        db = self.ip_db
        for k, v in db.items():
            if v == ip_num:
                ret_ip = self.int2ip(k)
                ip_found = True
        if ip_found:                # the entry already existed
            return ret_ip
        else:                       # the entry did not already exist
            if len(self.ip_db) > 0:
                new_ip = max(db.keys()) + 1
            else:
                new_ip = self._ip2int(self.start_ip)
            db[new_ip] = ip_num

            return self.int2ip(new_ip)

    def _obfuscate_line(self, line, obfs, ip_func):
        '''this will return a line with obfuscates for all possible variables, hostname, ip, etc.'''
        new_line = line
        if "ip" in obfs:
            new_line = ip_func(line)                 # IP substitution
        if "hostname" in obfs:
            new_line = self._sub_hostname(new_line)  # Hostname substitution
        if self.obfuscate and hasattr(self, 'kw_db'):
            # keywords obfuscate depends on "obfuscate=True"
            new_line = self._sub_keywords(new_line)  # Keyword Substitution
        return new_line

    def _redact_line(self, line):
        # patterns removal
        new_line = line
        exclude = self.redact['exclude']
        if exclude:
            find = re.search if self.redact['regex'] else lambda x, y: x in y
            if any(find(pat, new_line) for pat in exclude):
                # patterns found, remove it
                return None
        # password removal
        for rex in default_password_regexs:
            tmp_line = new_line
            new_line = re.sub(rex, r"\1\2********", tmp_line)
            if new_line != tmp_line:
                break
        return new_line

    def process_file(self, file, obfs):
        def _determine_ip_func(filepath):
            ip_func = self._sub_ip
            if file.endswith("netstat_-neopa"):
                ip_func = self._sub_ip_netstat
            return ip_func

        if file.endswith(('etc/insights-client/machine-id', 'etc/machine-id',
                          'insights_commands/subscription-manager_identity')):
            # do not redact or obfuscate the ID files
            return

        if obfs:
            logger.debug('Processing %s...', file)
        else:
            logger.debug('Redacting %s...', file)
            obfs = []

        if os.path.exists(file) and not os.path.islink(file):
            ip_func = _determine_ip_func(file)
            data = None
            tmp_file = TemporaryFile(mode='w+b')
            # Process it
            try:
                with open(file, 'r') as fh:
                    data = fh.readlines()
                    if data:
                        for line in data:
                            # Do Redaction without condition
                            new_l = self._redact_line(line)
                            if new_l is None:
                                # line is removed after redaction
                                continue
                            # Do Obfuscation as per the "obfs"
                            new_l = self._obfuscate_line(new_l, obfs, ip_func)
                            if six.PY3:
                                tmp_file.write(new_l.encode('utf-8'))
                            else:
                                tmp_file.write(new_l)
                        tmp_file.seek(0)
            except Exception as e:  # pragma: no cover
                logger.exception(e)
                raise Exception("Error: Cannot Open File For Obfuscating/Reading - %s" % file)
            # Store it
            try:
                if data:
                    with open(file, 'wb') as new_fh:
                        for line in tmp_file:
                            new_fh.write(line)
            except Exception as e:  # pragma: no cover
                logger.exception(e)
                raise Exception("Error: Cannot Write to New File - %s" % file)

            finally:
                tmp_file.close()
