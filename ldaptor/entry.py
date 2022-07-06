import abc
import base64
import random
from typing import List, Dict, Collection


from twisted.internet import defer
from twisted.python.util import InsensitiveDict
from zope.interface import implementer

from ldaptor import interfaces, attributeset, delta
from ldaptor._encoder import WireStrAlias, to_bytes, get_strings
from ldaptor.protocols.ldap import distinguishedname, ldif, ldaperrors
from ldaptor.protocols.ldap.distinguishedname import DistinguishedName
from ldaptor.attributeset import LDAPAttributeSet
from ldaptor.protocols.pureldap import (
    LDAPFilterMatchAll,
    LDAPFilter_and,
    LDAP_SCOPE_wholeSubtree,
    LDAP_DEREF_neverDerefAliases,
    LDAP_SCOPE_singleLevel,
    LDAP_SCOPE_baseObject,
)
from ldaptor.protocols.ldap.ldaperrors import LDAPProtocolError
from ldaptor.ldapfilter import parseFilter

from hashlib import sha1


def sshaDigest(passphrase, salt=None):
    """
    Return the salted SHA for `passphrase` which is passed as bytes.
    """
    if salt is None:
        salt = ""
        for i in range(8):
            salt += chr(random.randint(0, 127))
        salt = salt.encode("ascii")

    s = sha1()
    s.update(passphrase)
    s.update(salt)
    encoded = base64.encodebytes(s.digest() + salt).rstrip()
    crypt = b"{SSHA}" + encoded
    return crypt


class LdapEntry(abc.ABC):
    dn: DistinguishedName = None
    attributes: Dict[bytes, LDAPAttributeSet] = None

    def __init__(
        self, dn: DistinguishedName, attributes: Dict[bytes, Collection[bytes]]
    ) -> None:
        """Initialize an ldap entry.

        Note that this function will most often be called during evaluating
        'children' or 'lookup'.
        """
        self.dn = dn
        # TODO replace with a dict implementation with case-insensitive keys
        self.attributes = dict()
        for attribute, values in attributes.items():
            self.attributes[attribute] = LDAPAttributeSet(attribute, values)

    def __getitem__(self, key: bytes):
        return self.attributes.__getitem__(key)

    def __contains__(self, key: bytes):
        return self.attributes.__contains__(key)

    def __iter__(self):
        return self.attributes.__iter__()

    def keys(self):
        return self.attributes.keys()

    def values(self):
        return self.attributes.values()

    def items(self):
        return self.attributes.items()

    def __eq__(self, other):
        if not isinstance(other, LdapEntry):
            return NotImplemented
        if self.dn != other.dn:
            return False

        my_keys = sorted(self.keys())
        others_keys = sorted(other.keys())

        if my_keys != others_keys:
            return False
        for key in my_keys:
            if self[key] != other[key]:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def __len__(self):
        return self.attributes.__len__()

    # TODO which return type?
    @abc.abstractmethod
    async def bind(self, password: bytes) -> None:
        """Try to bind with the given password to this entry.

        :raises LDAPInvalidCredentials if the given passwort does not match.
        """

    @abc.abstractmethod
    async def children(self) -> List["LdapEntry"]:
        """List the direct children of this entry."""

    @abc.abstractmethod
    async def lookup(self, dn: DistinguishedName) -> "LdapEntry":
        """Lookup the given dn.

        :raises LDAPNoSuchObject if the given dn is not in the subtree of this dn.
        """

    # TODO filter type
    async def match(self, filter) -> bool:
        """Does this entry matches the given filter?"""

    async def subtree(self) -> List["LdapEntry"]:
        """List the subtree rooted at this entry, including this entry."""
        subtree = [self]
        children = await self.children()
        for child in children:
            subtree.extend(await child.subtree())
        return subtree

    # TODO what about the arguments which are currently never used?
    async def search(
        self,
        filter_text=None,
        filter_object=None,
        attributes=(),
        scope: int = None,
        deref_aliases: int = None,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: int = 0,
    ) -> List["LdapEntry"]:
        """Apply a search operation, rooted at this entry."""
        if filter_object is None and filter_text is None:
            filter_object = LDAPFilterMatchAll
        elif filter_object is None and filter_text is not None:
            filter_object = parseFilter(filter_text)
        elif filter_object is not None and filter_text is None:
            pass
        elif filter_object is not None and filter_text is not None:
            f = parseFilter(filter_text)
            filter_object = LDAPFilter_and((f, filter_object))

        if scope is None:
            scope = LDAP_SCOPE_wholeSubtree

        if deref_aliases is None:
            deref_aliases = LDAP_DEREF_neverDerefAliases

        if scope == LDAP_SCOPE_wholeSubtree:
            entries = await self.subtree()
        elif scope == LDAP_SCOPE_singleLevel:
            entries = await self.children()
        elif scope == LDAP_SCOPE_baseObject:
            entries = [self]
        else:
            raise LDAPProtocolError("unknown search scope: %r" % scope)

        return [entry for entry in entries if await entry.match(filter_object)]


@implementer(interfaces.ILDAPEntry)
class BaseLDAPEntry(WireStrAlias):
    dn = None
    _object_class_keys = set(get_strings("objectClass"))
    _object_class_lower_keys = set(get_strings("objectclass"))
    _user_password_keys = set(get_strings("userPassword"))

    def __init__(self, dn, attributes={}):
        """

        Initialize the object.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """
        self._attributes = InsensitiveDict()
        self.dn = distinguishedname.DistinguishedName(dn)

        for k, vs in attributes.items():
            if k not in self._attributes:
                self._attributes[k] = []
            self._attributes[k].extend(vs)

        for k, vs in self._attributes.items():
            self._attributes[k] = self.buildAttributeSet(k, vs)

    def buildAttributeSet(self, key, values):
        return attributeset.LDAPAttributeSet(key, values)

    def __getitem__(self, key):
        for k in get_strings(key):
            if k in self._attributes:
                return self._attributes[k]
        raise KeyError(key)

    def get(self, key, default=None):
        for k in get_strings(key):
            if k in self._attributes:
                return self._attributes[k]
        return default

    def has_key(self, key):
        for k in get_strings(key):
            if k in self._attributes:
                return True
        return False

    def __contains__(self, key):
        return self.has_key(key)

    def __iter__(self):
        yield from self._attributes.iterkeys()

    def keys(self):
        a = []
        for key in self._object_class_keys:
            if key in self._attributes:
                a.append(key)
        l = list(self._attributes.keys())
        l.sort(key=to_bytes)
        for key in l:
            if key.lower() not in self._object_class_lower_keys:
                a.append(key)
        return a

    def items(self):
        a = []

        for key in self._object_class_keys:
            objectClasses = list(self._attributes.get(key, []))
            objectClasses.sort(key=to_bytes)
            if objectClasses:
                a.append((key, objectClasses))

        l = list(self._attributes.items())
        l.sort(key=lambda x: to_bytes(x[0]))
        for key, values in l:
            if key.lower() not in self._object_class_lower_keys:
                vs = list(values)
                vs.sort()
                a.append((key, vs))

        return a

    def toWire(self):
        a = []

        for key in self._object_class_keys:
            objectClasses = list(self._attributes.get(key, []))
            objectClasses.sort(key=to_bytes)
            a.append((key, objectClasses))

        items_gen = ((key, self[key]) for key in self)
        items = sorted(items_gen, key=lambda x: to_bytes(x[0]))
        for key, values in items:
            if key.lower() not in self._object_class_lower_keys:
                vs = list(values)
                vs.sort()
                a.append((key, vs))
        return ldif.asLDIF(self.dn.getText(), a)

    def getLDIF(self):
        return self.toWire().decode("utf-8")

    def __eq__(self, other):
        if not isinstance(other, BaseLDAPEntry):
            return NotImplemented
        if self.dn != other.dn:
            return 0

        my = sorted((key for key in self), key=to_bytes)
        its = sorted((key for key in other), key=to_bytes)
        if my != its:
            return 0
        for key in my:
            myAttr = self[key]
            itsAttr = other[key]
            if myAttr != itsAttr:
                return 0
        return 1

    def __ne__(self, other):
        return not self == other

    def __len__(self):
        return len(self.keys())

    def __bool__(self):
        return True

    def __nonzero__(self):
        return self.__bool__()

    def __repr__(self):
        keys = sorted((key for key in self), key=to_bytes)
        a = []
        for key in keys:
            a.append(f"{repr(key)}: {repr(list(self[key]))}")
        attributes = ", ".join(a)
        dn = self.dn.getText()
        return f"{self.__class__.__name__}({repr(dn)}, {{{attributes}}})"

    def diff(self, other):
        """
        Compute differences between this and another LDAP entry.

        @param other: An LDAPEntry to compare to.

        @return: None if equal, otherwise a ModifyOp that would make
        this entry look like other.
        """
        assert self.dn == other.dn
        if self == other:
            return None

        r = []

        myKeys = {key for key in self}
        otherKeys = {key for key in other}

        addedKeys = list(otherKeys - myKeys)
        addedKeys.sort(key=to_bytes)  # for reproducability only
        for added in addedKeys:
            r.append(delta.Add(added, other[added]))

        deletedKeys = list(myKeys - otherKeys)
        deletedKeys.sort(key=to_bytes)  # for reproducability only
        for deleted in deletedKeys:
            r.append(delta.Delete(deleted, self[deleted]))

        sharedKeys = list(myKeys & otherKeys)
        sharedKeys.sort(key=to_bytes)  # for reproducability only
        for shared in sharedKeys:

            addedValues = list(other[shared] - self[shared])
            if addedValues:
                addedValues.sort(key=to_bytes)  # for reproducability only
                r.append(delta.Add(shared, addedValues))

            deletedValues = list(self[shared] - other[shared])
            if deletedValues:
                deletedValues.sort(key=to_bytes)  # for reproducability only
                r.append(delta.Delete(shared, deletedValues))

        return delta.ModifyOp(dn=self.dn, modifications=r)

    def bind(self, password):
        return defer.maybeDeferred(self._bind, password)

    def _bind(self, password):
        password = to_bytes(password)
        for key in self._user_password_keys:
            for digest in self.get(key, ()):
                digest = to_bytes(digest)
                if digest.startswith(b"{SSHA}"):
                    raw = base64.decodebytes(digest[len(b"{SSHA}") :])
                    salt = raw[20:]
                    got = sshaDigest(password, salt)
                    if got == digest:
                        return self
                else:
                    # Plaintext
                    if digest == password:
                        return self
        raise ldaperrors.LDAPInvalidCredentials()

    def hasMember(self, dn):
        for memberDN in self.get("member", []):
            if memberDN == dn:
                return True
        return False

    def __hash__(self):
        # FIXME:https://github.com/twisted/ldaptor/issues/101
        # The hash should take into consideration any attribute used to
        # decide the equality.
        return hash(self.dn)


@implementer(interfaces.IEditableLDAPEntry)
class EditableLDAPEntry(BaseLDAPEntry):
    def __setitem__(self, key, value):
        new = self.buildAttributeSet(key, value)
        self._attributes[key] = new

    def __delitem__(self, key):
        del self._attributes[key]

    def undo(self):
        raise NotImplementedError()

    def commit(self):
        raise NotImplementedError()

    def move(self, newDN):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    def setPassword(self, newPasswd, salt=None):
        """
        Update the password for the entry with a new password and salt passed
        as bytes.
        """
        crypt = sshaDigest(newPasswd, salt)
        for key in self._user_password_keys:
            if key in self:
                self[key] = [crypt]
        else:
            self[b"userPassword"] = [crypt]
