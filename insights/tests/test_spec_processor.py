from mock.mock import patch
from pytest import mark

from insights.client.config import InsightsConfig
from insights.util.spec_processor import PostProcessor


@mark.parametrize(("line", "expected"), [
    ("radius_ip_1=10.0.0.1", "radius_ip_1=10.230.230.1"),
    (
        (
            "        inet 10.0.2.15"
            "  netmask 255.255.255.0"
            "  broadcast 10.0.2.255"
        ),
        (
            "        inet 10.230.230.3"
            "  netmask 10.230.230.1"
            "  broadcast 10.230.230.2"
        ),
    ),
    (
        "radius_ip_1=10.0.0.100-10.0.0.200",
        "radius_ip_1=10.230.230.1-10.230.230.2",
    ),
])
def test_obfuscate_ip_match(line, expected):
    c = InsightsConfig(obfuscate=True)
    pp = PostProcessor(c, {})
    actual = pp._obfuscate_line(line, ['ip'], pp._sub_ip)
    assert actual == expected


@mark.parametrize(("line", "expected"), [
    (
        (
            "        inet 10.0.2.155"
            "  netmask 10.0.2.1"
            "  broadcast 10.0.2.15"
        ),
        (
            "        inet 10.230.230.1"
            "  netmask 10.230.230.3"
            "  broadcast 10.230.230.2"
        ),
    ),
])
def test_obfuscate_ip_match_IP_overlap(line, expected):
    c = InsightsConfig(obfuscate=True)
    pp = PostProcessor(c, {})
    actual = pp._obfuscate_line(line, ['ip'], pp._sub_ip)
    assert actual == expected


@mark.parametrize(("line", "expected"), [
    (
        "tcp6       0      0 10.0.0.1:23           10.0.0.110:63564   ESTABLISHED 0",
        "tcp6       0      0 10.230.230.2:23       10.230.230.1:63564 ESTABLISHED 0"
    ),
    (
        "tcp6  10.0.0.11    0 10.0.0.1:23       10.0.0.111:63564    ESTABLISHED 0",
        "tcp6  10.230.230.2 0 10.230.230.3:23   10.230.230.1:63564  ESTABLISHED 0"
    ),
    (
        "unix  2      [ ACC ]     STREAM     LISTENING     43279    2070/snmpd         172.31.0.1\n",
        "unix  2      [ ACC ]     STREAM     LISTENING     43279    2070/snmpd         10.230.230.1\n"
    ),
    (
        "unix  2      [ ACC ]     STREAM     LISTENING     43279    2070/snmpd         172.31.111.11\n",
        "unix  2      [ ACC ]     STREAM     LISTENING     43279    2070/snmpd         10.230.230.1 \n"
    ),
])
def test_obfuscate_ip_match_IP_overlap_netstat(line, expected):
    c = InsightsConfig(obfuscate=True)
    pp = PostProcessor(c, {})
    actual = pp._obfuscate_line(line, ['ip'], pp._sub_ip_netstat)
    assert actual == expected


@mark.parametrize(("original", "expected"), [
    (
        "{\"name\":\"shadow-utils\","
        "\"epoch\":\"2\","
        "\"version\":\"4.1.5.1\","
        "\"release\":\"5.el6\","
        "\"arch\":\"x86_64\","
        "\"installtime\":\"Wed 13 Jan 2021 10:04:18 AM CET\","
        "\"buildtime\":\"1455012203\","
        "\"vendor\":\"Red Hat, Inc.\","
        "\"buildhost\":\"x86-027.build.eng.bos.redhat.com\","
        "\"sigpgp\":"
        "\"RSA/8, "
        "Tue 08 Mar 2016 11:15:08 AM CET, "
        "Key ID 199e2f91fd431d51\"}",

        "{\"name\":\"shadow-utils\","
        "\"epoch\":\"2\","
        "\"version\":\"10.230.230.1\","
        "\"release\":\"5.el6\","
        "\"arch\":\"x86_64\","
        "\"installtime\":\"Wed 13 Jan 2021 10:04:18 AM CET\","
        "\"buildtime\":\"1455012203\","
        "\"vendor\":\"Red Hat, Inc.\","
        "\"buildhost\":\"x86-027.build.eng.bos.redhat.com\","
        "\"sigpgp\":"
        "\"RSA/8, "
        "Tue 08 Mar 2016 11:15:08 AM CET, "
        "Key ID 199e2f91fd431d51\"}",
    )
])
@patch("insights.util.spec_processor.PostProcessor._ip2db", return_value="10.230.230.1")
def test_obfuscate_ip_false_positive(_ip2db, original, expected):
    c = InsightsConfig(obfuscate=True)
    pp = PostProcessor(c, {})
    actual = pp._obfuscate_line(original, ['ip'], pp._sub_ip)
    assert actual == expected
    # BUT works well without "obfuscate=['ip']
    actual = pp._obfuscate_line(original, [], pp._sub_ip)
    assert actual == original


def test_obfuscate_hostname():
    hostname = 'test1.abc.com'
    line = "a line with %s here" % hostname
    c = InsightsConfig(obfuscate=True, obfuscate_hostname=True, hostname=hostname)
    pp = PostProcessor(c, {}, hostname)
    actual = pp._obfuscate_line(line, ['hostname'], None)
    assert 'test1' not in actual
    assert 'host1.domain1' in actual


@mark.parametrize(("line", "expected"), [
    (
        "test1.abc.com, 10.0.0.1 test1.abc.loc, 20.1.4.7 smtp.abc.com, 10.1.2.7 lite.def.com",
        "host1.domain1.com, 10.230.230.1 host2.domain2.com, 10.230.230.2 host3.domain1.com, 10.230.230.3 host4.domain3.com"
    ),
])
def test_obfuscate_hostname_and_ip(line, expected):
    hostname = 'test1.abc.com'
    c = InsightsConfig(obfuscate=True, obfuscate_hostname=True, hostname=hostname)
    pp = PostProcessor(c, {}, hostname)
    actual = pp._obfuscate_line(line, ['hostname', 'ip'], pp._sub_ip)
    assert actual == expected


@mark.parametrize(("line", "expected"), [
    (
        "what's your name? what day is today?",
        "what's your keyword0? what keyword1 is tokeyword1?"
    ),
])
def test_obfuscate_keyword(line, expected):
    c = InsightsConfig(obfuscate=True)
    pp = PostProcessor(c, {'keywords': ['name', 'day']})
    actual = pp._obfuscate_line(line, [], None)
    assert actual == expected


@mark.parametrize(("line", "expected"), [
    (
        "test1.abc.com, 10.0.0.1 test1.abc.loc, 20.1.4.7 smtp.abc.com, what's your name? what day is today?",
        "host1.domain1.com, 10.230.230.1 host2.domain2.com, 10.230.230.2 host3.domain1.com, what's your keyword0? what keyword1 is tokeyword1?"
    ),
])
def test_obfuscate_keyword_hostname_and_ip(line, expected):
    hostname = 'test1.abc.com'
    c = InsightsConfig(obfuscate=True, obfuscate_hostname=True, hostname=hostname)
    pp = PostProcessor(c, {'keywords': ['name', 'day']}, hostname)
    actual = pp._obfuscate_line(line, ['hostname', 'ip'], pp._sub_ip)
    assert actual == expected


@mark.parametrize(("line", "expected"), [
    ("test1.abc.com: it's myserver? what is yours?", None),
    ("testabc: it's mykey? what is yours?", None),
    (
        "testabc: it's my1key? what is yours?",
        "testabc: it's my1key? what is yours?",
    ),
])
def test_redact_exclude_patterns(line, expected):
    c = InsightsConfig()
    pp = PostProcessor(c, {'patterns': ['myserver', 'mykey']})
    actual = pp._redact_line(line)
    assert actual is expected


@mark.parametrize(("line", "expected"), [
    ("test1.abc.com: it's myserver? what is yours?", None),
    ("testabc: it's mykey? what is yours?", None),
    ("testabc: it's my1key? what is yours?", None),
])
def test_redact_patterns_regex(line, expected):
    c = InsightsConfig()
    pp = PostProcessor(c, {'patterns': {'regex': ['myserver', 'my(\w*)key']}})
    actual = pp._redact_line(line)
    assert actual is expected


@mark.parametrize(("line", "expected"), [
    ("password: p@ss_W0rd ?", "password: ******** ?"),
    ("password = p@ss_W0rd ?", "password = ******** ?"),
    ("password=p@ss_W0-d", "password=********"),
])
def test_redact_password(line, expected):
    c = InsightsConfig()
    pp = PostProcessor(c, {'patterns': {'regex': ['myserver', 'my(\w*)key']}})
    actual = pp._redact_line(line)
    assert actual == expected
