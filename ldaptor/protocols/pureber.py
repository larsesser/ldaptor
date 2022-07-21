"""Pure, simple, BER encoding and decoding"""

# This BER library is currently aimed at supporting LDAP, thus
# the following restrictions from RFC2251 apply:
#
# (1) Only the definite form of length encoding will be used.
#
# (2) OCTET STRING values will be encoded in the primitive form
#     only.
#
# (3) If the value of a BOOLEAN type is true, the encoding MUST have
#     its contents octets set to hex "FF".
#
# (4) If a value of a type is its default value, it MUST be absent.
#     Only some BOOLEAN and INTEGER types have default values in
#     this protocol definition.

import abc
from typing import Tuple, Optional, List, Type, Any, TypeVar, Iterable, Mapping
from collections import UserList

from ldaptor._encoder import to_bytes, WireStrAlias

# xxxxxxxx
# |/|\.../
# | | |
# | | tag
# | |
# | primitive (0) or structured (1)
# |
# class

CLASS_MASK = 0xC0
CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80
CLASS_PRIVATE = 0xC0

STRUCTURED_MASK = 0x20
STRUCTURED = 0x20
NOT_STRUCTURED = 0x00

TAG_MASK = 0x1F


# LENGTH
# 0xxxxxxx = 0..127
# 1xxxxxxx = len is stored in the next 0xxxxxxx octets
# indefinite form not supported


class UnknownBERTag(Exception):
    def __init__(self, tag, context):
        Exception.__init__(self)
        self.tag = tag
        self.context = context

    def __str__(self):
        return "BERDecoderContext has no tag 0x{:02x}: {}".format(
            self.tag, self.context
        )


def berDecodeLength(m: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Return a tuple of (length, lengthLength).
    m must be atleast one byte long.
    """
    l = ber2int(m[offset + 0 : offset + 1])
    ll = 1
    if l & 0x80:
        ll = 1 + (l & 0x7F)
        need(m, offset + ll)
        l = ber2int(m[offset + 1 : offset + ll], signed=False)
    return (l, ll)


def int2berlen(i: int) -> bytes:
    assert i >= 0
    e = int2ber(i, signed=False)
    if i <= 127:
        return e
    else:
        l = len(e)
        assert l > 0
        assert l <= 127
        return bytes((0x80 | l,)) + e


def int2ber(i: int, signed: bool = True) -> bytes:
    encoded = b""
    while (signed and (i > 127 or i < -128)) or (not signed and (i > 255)):
        encoded = bytes((i % 256,)) + encoded
        i = i >> 8
    encoded = bytes((i % 256,)) + encoded
    return encoded


def ber2int(e: bytes, signed: bool = True) -> int:
    need(e, 1)
    v = 0 + ord(e[0:1])
    if v & 0x80 and signed:
        v = v - 256
    for i in range(1, len(e)):
        v = (v << 8) | ord(e[i : i + 1])
    return v


T = TypeVar("T")


def validate_ber(val: Optional["BERBase"], type_: Type[T]) -> T:
    """Validate that the given value has the expected type."""
    if val is None:
        raise ValueError("Values must not be None.")
    if not isinstance(val, type_):
        raise TypeError(f"Expected {type_}, got {type(val)}.")
    return val


class BERBase(WireStrAlias, metaclass=abc.ABCMeta):
    tag: int
    value: Any

    def identification(self) -> int:
        return self.tag

    def __init__(self, tag: int = None):
        if tag is not None:
            self.tag = tag

    def __len__(self):
        return len(self.toWire())

    def __eq__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.toWire() == other.toWire()

    def __ne__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented

        return self.toWire() != other.toWire()

    def __hash__(self):
        return hash(self.toWire())

    @classmethod
    def fromBER(
        cls, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BERBase":
        """Create an instance of this class from a binary string.

        This is the default way an instance of this class will be created.
        """
        raise NotImplementedError

    def toWire(self) -> bytes:
        """Encode the instance of this class to its binary value."""
        return b""


class BERStructured(BERBase):
    def identification(self):
        return STRUCTURED | self.tag


class BERException(Exception):
    pass


class BERExceptionInsufficientData(Exception):
    pass


def need(buf: bytes, n: int) -> None:
    d = n - len(buf)
    if d > 0:
        raise BERExceptionInsufficientData(d)


class BERInteger(BERBase):
    tag = 0x02
    value: int

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BERInteger":
        if len(content) <= 0:
            raise ValueError
        value = ber2int(content)
        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value: int, tag: int = None):
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        if value is None:
            raise ValueError
        self.value = value

    def toWire(self) -> bytes:
        encoded = int2ber(self.value)
        return bytes((self.identification(),)) + int2berlen(len(encoded)) + encoded

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" % (
                self.value,
                self.tag,
            )


class BEROctetString(BERBase):
    tag = 0x04
    value: bytes

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BEROctetString":
        assert len(content) >= 0
        r = klass(value=content, tag=tag)
        return r

    def __init__(self, value: bytes, tag: int = None):
        BERBase.__init__(self, tag)
        if value is None:
            raise ValueError
        # TODO convert to bytes!
        self.value = value

    def toWire(self) -> bytes:
        value = to_bytes(self.value)
        result = bytes((self.identification(),)) + int2berlen(len(value)) + value
        return result

    def __repr__(self):
        value = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(value),
                self.tag,
            )


class BERNull(BERBase):
    tag = 0x05

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BERNull":
        if len(content) != 0:
            raise ValueError
        r = klass(tag=tag)
        return r

    def __init__(self, tag: int = None):
        BERBase.__init__(self, tag)

    def toWire(self) -> bytes:
        return bytes((self.identification(),)) + bytes((0,))

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "()"
        else:
            return self.__class__.__name__ + "(tag=%d)" % self.tag


class BERBoolean(BERBase):
    tag = 0x01
    value: bool

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BERBoolean":
        if len(content) <= 0:
            raise ValueError
        value = ber2int(content)
        r = klass(value=bool(value), tag=tag)
        return r

    def __init__(self, value: bool, tag: int = None):
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        if value is None:
            raise ValueError
        # TODO convert value to bool
        self.value = value

    def toWire(self) -> bytes:
        value = 0xFF if self.value else 0
        return bytes((self.identification(),)) + int2berlen(1) + bytes((value,))

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%d)" % self.value
        else:
            return self.__class__.__name__ + "(value=%d, tag=%d)" % (
                self.value,
                self.tag,
            )


# TODO use IntEnums to represent enumerates
class BEREnumerated(BERInteger):
    tag = 0x0A


class BERSequence(BERStructured, UserList):
    # TODO __getslice__ calls __init__ with no args.
    tag = 0x10

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: "BERDecoderContext"
    ) -> "BERSequence":
        vals = berDecodeMultiple(content, berdecoder)
        seq = [validate_ber(val, BERBase) for val in vals]
        r = klass(seq, tag=tag)
        return r

    # TODO type of value?
    def __init__(self, value: Iterable[BERBase], tag: int = None):
        BERStructured.__init__(self, tag)
        if value is None:
            raise ValueError
        UserList.__init__(self, value)

    def toWire(self) -> bytes:
        r = b"".join(to_bytes(x) for x in self.data)
        return bytes((self.identification(),)) + int2berlen(len(r)) + r

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.data)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.data),
                self.tag,
            )


# TODO ?
class BERSequenceOf(BERSequence):
    pass


class BERSet(BERSequence):
    tag = 0x11


class BERDecoderContext:
    Identities: Mapping[int, Type[BERBase]] = {
        BERBoolean.tag: BERBoolean,
        BERInteger.tag: BERInteger,
        BEROctetString.tag: BEROctetString,
        BERNull.tag: BERNull,
        BEREnumerated.tag: BEREnumerated,
        BERSequence.tag: BERSequence,
        BERSet.tag: BERSet,
    }

    def __init__(
        self, fallback: "BERDecoderContext" = None, inherit: "BERDecoderContext" = None
    ) -> None:
        self.fallback = fallback
        self.inherit_context = inherit

    def lookup_id(self, id: int) -> Optional[Type[BERBase]]:
        try:
            return self.Identities[id]
        except KeyError:
            if self.fallback:
                return self.fallback.lookup_id(id)
            else:
                return None

    def inherit(self) -> "BERDecoderContext":
        return self.inherit_context or self

    def __repr__(self):
        identities = []
        for tag, class_ in self.Identities.items():
            identities.append(f"0x{tag:02x}: {class_.__name__}")

        return (
            "<"
            + self.__class__.__name__
            + " identities={%s}" % ", ".join(identities)
            + " fallback="
            + repr(self.fallback)
            + " inherit="
            + repr(self.inherit_context)
            + ">"
        )


def berDecodeObject(
    context: BERDecoderContext, m: bytes
) -> Tuple[Optional[BERBase], int]:
    """berDecodeObject(context, bytes) -> (berobject, bytesUsed)
    berobject may be None.
    """
    while m:
        need(m, 2)
        i = ber2int(m[0:1], signed=False) & (CLASS_MASK | TAG_MASK)

        length, lenlen = berDecodeLength(m, offset=1)
        need(m, 1 + lenlen + length)
        m2 = m[1 + lenlen : 1 + lenlen + length]

        berclass = context.lookup_id(i)
        if berclass:
            inh = context.inherit()
            assert inh
            r = berclass.fromBER(tag=i, content=m2, berdecoder=inh)
            return (r, 1 + lenlen + length)
        else:
            print(str(UnknownBERTag(i, context)))  # TODO
            return (None, 1 + lenlen + length)
    return (None, 0)


def berDecodeMultiple(content: bytes, berdecoder: BERDecoderContext) -> List[BERBase]:
    """berDecodeMultiple(content, berdecoder) -> [objects]

    Decodes everything in content and returns a list of decoded
    objects.

    All of content will be decoded, and content must contain complete
    BER objects.
    """
    l = []
    while content:
        n, bytes = berDecodeObject(berdecoder, content)
        if n is not None:
            l.append(n)
        assert bytes <= len(content)
        content = content[bytes:]
    return l


# TODO unimplemented classes are below:

# class BERObjectIdentifier(BERBase):
#    tag = 0x06
#    pass

# class BERIA5String(BERBase):
#    tag = 0x16
#    pass

# class BERPrintableString(BERBase):
#    tag = 0x13
#    pass

# class BERT61String(BERBase):
#    tag = 0x14
#    pass

# class BERUTCTime(BERBase):
#    tag = 0x17
#    pass

# class BERBitString(BERBase):
#    tag = 0x03
#    pass
