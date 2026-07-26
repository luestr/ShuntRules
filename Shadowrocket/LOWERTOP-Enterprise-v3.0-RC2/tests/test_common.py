import unittest

from scripts.common import matches, parse_rule


class RuleMatchingTests(unittest.TestCase):
    def test_domain_suffix_matches_root_and_subdomain(self):
        rule = parse_rule("DOMAIN-SUFFIX,apple.com")
        self.assertTrue(matches(rule, {"host": "apple.com"}))
        self.assertTrue(matches(rule, {"host": "push.apple.com"}))
        self.assertFalse(matches(rule, {"host": "notapple.com"}))

    def test_domain_exact(self):
        rule = parse_rule("DOMAIN,mask.icloud.com")
        self.assertTrue(matches(rule, {"host": "mask.icloud.com"}))
        self.assertFalse(matches(rule, {"host": "x.mask.icloud.com"}))

    def test_keyword(self):
        rule = parse_rule("DOMAIN-KEYWORD,openai")
        self.assertTrue(matches(rule, {"host": "ios.chat.openai.com"}))
        self.assertTrue(matches(rule, {"host": "example-openai.invalid"}))

    def test_ip_cidr(self):
        rule = parse_rule("IP-CIDR,10.0.0.0/8")
        self.assertTrue(matches(rule, {"ip": "10.2.3.4"}))
        self.assertFalse(matches(rule, {"ip": "11.2.3.4"}))


if __name__ == "__main__":
    unittest.main()
