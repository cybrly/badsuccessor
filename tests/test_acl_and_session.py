import os, sys, uuid, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from impacket.ldap import ldaptypes
import badsuccessor as bs

DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
OTHER_GUID = "bf967aba-0de6-11d0-a285-00aa003049e2"  # user class
CREATE_CHILD = 0x1


def make_ace(ace_type, mask, sid="S-1-5-21-1-2-3-1104", object_guid=None):
    ace = ldaptypes.ACE()
    ace['AceType'] = ace_type
    ace['AceFlags'] = 0
    if ace_type == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
        inner = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        inner['Flags'] = 0
        if object_guid:
            inner['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
            inner['ObjectType'] = uuid.UUID(object_guid).bytes_le
        inner['InheritedObjectType'] = b''
    else:
        inner = ldaptypes.ACCESS_ALLOWED_ACE()
    m = ldaptypes.ACCESS_MASK(); m['Mask'] = mask; inner['Mask'] = m
    s = ldaptypes.LDAP_SID(); s.fromCanonical(sid); inner['Sid'] = s
    ace['Ace'] = inner
    return ace


class Checker(bs.ACLPermissionChecker):
    def __init__(self):
        # skip network __init__
        self.dmsa_schema_guid = DMSA_GUID
        self.user_sid = "S-1-5-21-1-2-3-1104"
        self.username = "t"


class ACEPermissionTests(unittest.TestCase):
    def setUp(self):
        self.c = Checker()

    def test_object_ace_dmsa_create_is_detected(self):
        ace = make_ace(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, CREATE_CHILD, object_guid=DMSA_GUID)
        p = self.c._check_ace_permissions(ace)
        self.assertTrue(p['create_child'])
        self.assertTrue(p['create_dmsa'])

    def test_object_ace_other_class_is_not_dmsa(self):
        ace = make_ace(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, CREATE_CHILD, object_guid=OTHER_GUID)
        p = self.c._check_ace_permissions(ace)
        self.assertTrue(p['create_child'])
        self.assertFalse(p['create_dmsa'])

    def test_object_ace_no_objecttype_covers_dmsa(self):
        ace = make_ace(ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, CREATE_CHILD, object_guid=None)
        p = self.c._check_ace_permissions(ace)
        self.assertTrue(p['create_dmsa'])

    def test_plain_allowed_ace_still_works(self):
        ace = make_ace(ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, CREATE_CHILD)
        p = self.c._check_ace_permissions(ace)
        self.assertTrue(p['create_child'])
        self.assertTrue(p['create_dmsa'])

    def test_generic_all_implies_everything(self):
        ace = make_ace(ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, bs.ACLPermissionChecker.ADS_RIGHT_GENERIC_ALL)
        p = self.c._check_ace_permissions(ace)
        self.assertTrue(p['generic_all'] and p['create_dmsa'] and p['full_control'])

    def test_deny_ace_ignored(self):
        ace = make_ace(ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE, CREATE_CHILD)
        p = self.c._check_ace_permissions(ace)
        self.assertFalse(any(v for k, v in p.items() if k != 'effective_permissions'))


class GuidTests(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(bs.guid_bytes_to_string(uuid.UUID(DMSA_GUID).bytes_le), DMSA_GUID)

    def test_bad_input(self):
        self.assertIsNone(bs.guid_bytes_to_string(b'short'))
        self.assertIsNone(bs.guid_bytes_to_string(None))


class SessionTests(unittest.TestCase):
    def test_json_roundtrip_and_perms(self):
        with tempfile.TemporaryDirectory() as d:
            sm = bs.SessionManager(session_dir=os.path.join(d, "s"))
            sid = sm.new_session("corp.local", "alice")
            sm.add_created_dmsa("CN=x,OU=y,DC=corp,DC=local", "x", "OU=y,DC=corp,DC=local")
            self.assertEqual(oct(os.stat(sm.session_file).st_mode)[-3:], "600")
            sm2 = bs.SessionManager(session_dir=os.path.join(d, "s"))
            self.assertTrue(sm2.load_session(sid))
            self.assertEqual(len(sm2.state['created_dmsas']), 1)
            self.assertEqual(len(sm2.get_all_sessions()), 1)

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            sm = bs.SessionManager(session_dir=os.path.join(d, "s"))
            for bad in ("../evil", "a/b", "..", "x\\y"):
                with self.assertRaises(ValueError):
                    sm.load_session(bad)


if __name__ == "__main__":
    unittest.main()
