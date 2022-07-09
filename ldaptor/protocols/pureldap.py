"""LDAP protocol message conversion; no application logic here."""
import abc
import string
from typing import Callable, List, Type, Tuple, Optional, Union, Mapping


from ldaptor.protocols.pureber import (
    BERBase,
    BERBoolean,
    BERDecoderContext,
    BEREnumerated,
    BERInteger,
    BERNull,
    BEROctetString,
    BERSequence,
    BERSequenceOf,
    BERSet,
    BERStructured,
    CLASS_APPLICATION,
    CLASS_CONTEXT,
    berDecodeMultiple,
    berDecodeObject,
    int2berlen,
    validate_ber,
)
from ldaptor._encoder import to_bytes

EscaperCallable = Callable[[str], str]

next_ldap_message_id = 1


def alloc_ldap_message_id() -> int:
    global next_ldap_message_id
    r = next_ldap_message_id
    next_ldap_message_id = next_ldap_message_id + 1
    return r


def escape(s: str) -> str:
    s = s.replace("\\", r"\5c")
    s = s.replace("*", r"\2a")
    s = s.replace("(", r"\28")
    s = s.replace(")", r"\29")
    s = s.replace("\0", r"\00")
    return s


# TODO type of s?
def binary_escape(s) -> str:
    return "".join(f"\\{ord(c):02x}" for c in s)


def smart_escape(s, threshold=0.30):
    binary_count = sum(c not in string.printable for c in s)
    if float(binary_count) / float(len(s)) > threshold:
        return binary_escape(s)

    return escape(s)


class LDAPInteger(BERInteger):
    pass


class LDAPString(BEROctetString):
    escaper: EscaperCallable = None  # type: ignore[assignment]

    def __init__(self, *args, **kwargs):
        self.escaper = kwargs.pop("escaper", escape)
        super().__init__(*args, **kwargs)


class LDAPAttributeValue(BEROctetString):
    pass


class LDAPMessage(BERSequence):
    """
    To encode this object in order to be sent over the network use the toWire()
    method.
    """

    id: int = None  # type: ignore[assignment]
    value: "LDAPProtocolOp" = None  # type: ignore[assignment]

    @classmethod
    def fromBER(
        cls, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPMessage":
        vals = berDecodeMultiple(content, berdecoder)

        id_ = validate_ber(vals[0], BERInteger)
        msg = validate_ber(vals[1], LDAPProtocolOp)

        if len(vals) > 2:
            # TODO why not use LDAPControls directly here?
            raw_controls = validate_ber(vals[2], BERSequence)
            controls = []
            for raw_control in raw_controls:
                control = validate_ber(raw_control, LDAPControl)
                controls.append(
                    (control.controlType, control.criticality, control.controlValue)
                )
        else:
            controls = None

        if len(vals) > 3:
            raise ValueError

        r = cls(id=id_.value, value=msg, controls=controls, tag=tag)
        return r

    def __init__(
        self,
        value: "LDAPProtocolOp" = None,
        controls: "LDAPControls" = None,
        id: int = None,
        tag: int = None,
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert value is not None
        if id is None:
            id = alloc_ldap_message_id()
        self.id = id
        self.value = value
        self.controls = controls

    def toWire(self) -> bytes:
        """
        This is the wire/encoded representation.
        """
        l = [BERInteger(self.id), self.value]
        if self.controls is not None:
            l.append(LDAPControls([LDAPControl(*a) for a in self.controls]))
        return BERSequence(l).toWire()

    def __repr__(self):
        l = []
        l.append("id=%r" % self.id)
        l.append("value=%r" % self.value)
        l.append("controls=%r" % self.controls)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPProtocolOp(BERBase, metaclass=abc.ABCMeta):
    pass


class LDAPProtocolRequest(LDAPProtocolOp, metaclass=abc.ABCMeta):
    # TODO make this a bool?
    needs_answer = 1


class LDAPProtocolResponse(LDAPProtocolOp, metaclass=abc.ABCMeta):
    pass


class LDAPBERDecoderContext_LDAPBindRequest(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x03: BERSequence,
    }


class LDAPBindRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x00
    version: int
    dn: bytes
    auth: Union[bytes, Tuple[bytes, Optional[bytes]]]
    sasl: bool

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPBindRequest":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder)
        )
        version = validate_ber(vals[0], BERInteger)
        dn = validate_ber(vals[1], BEROctetString)
        raw_auth = vals[2]

        auth: Optional[Union[bytes, Tuple[bytes, Optional[bytes]]]]
        sasl = False
        if isinstance(raw_auth, BEROctetString):
            auth = raw_auth.value
        elif isinstance(raw_auth, BERSequence):
            mechanism = validate_ber(raw_auth[0], BEROctetString)
            # per https://ldap.com/ldapv3-wire-protocol-reference-bind/
            # Credentials are optional and not always provided
            if len(raw_auth.data) == 2:
                credentials = validate_ber(raw_auth[1], BEROctetString)
                auth = (mechanism.value, credentials.value)
            else:
                auth = (mechanism.value, None)
            sasl = True
        else:
            auth = None

        r = klass(version=version.value, dn=dn.value, auth=auth, tag=tag, sasl=sasl)
        return r

    def __init__(
        self,
        version: int = None,
        dn: bytes = None,
        auth: Union[bytes, Tuple[bytes, Optional[bytes]]] = None,
        tag: int = None,
        sasl: bool = False,
    ):
        """Constructor for LDAP Bind Request

        For sasl=False, pass a string password for 'auth'
        For sasl=True, pass a tuple of (mechanism, credentials) for 'auth'"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        if version is None:
            version = 3
        self.version = version
        if dn is None:
            dn = ""
        self.dn = dn
        if auth is None:
            auth = ""
            assert not sasl
        self.auth = auth
        self.sasl = sasl

    def toWire(self) -> bytes:
        auth_ber: Union[BEROctetString, BERSequence]
        if not self.sasl:
            auth_ber = BEROctetString(self.auth, tag=CLASS_CONTEXT | 0)
        else:
            # since the credentails for SASL is optional must check first
            # if credentials are None don't send them.
            if self.auth[1]:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0]), BEROctetString(self.auth[1])],
                    tag=CLASS_CONTEXT | 3,
                )
            else:
                auth_ber = BERSequence(
                    [BEROctetString(self.auth[0])], tag=CLASS_CONTEXT | 3
                )
        return BERSequence(
            [
                BERInteger(self.version),
                BEROctetString(self.dn),
                auth_ber,
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        auth = "*" * len(self.auth)
        l = []
        l.append("version=%d" % self.version)
        l.append("dn=%s" % repr(self.dn))
        l.append("auth=%s" % repr(auth))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        l.append("sasl=%s" % repr(self.sasl))
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPReferral(BERSequence):
    tag = CLASS_CONTEXT | 0x03


class LDAPBERDecoderContext_LDAPSearchResultReference(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        BEROctetString.tag: LDAPString,
    }


class LDAPSearchResultReference(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x13
    uris: List[LDAPString]

    def __init__(self, uris: List[LDAPString] = None, tag: int = None):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert uris is not None
        self.uris = uris

    @classmethod
    def fromBER(
        cls, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPSearchResultReference":
        vals = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_LDAPSearchResultReference(fallback=berdecoder),
        )
        uris = [validate_ber(val, LDAPString) for val in vals]
        r = cls(uris=uris)
        return r

    def toWire(self) -> bytes:
        return BERSequence(BERSequence(self.uris), tag=self.tag).toWire()

    def __repr__(self):
        return "{}(uris={}{})".format(
            self.__class__.__name__,
            repr([uri for uri in self.uris]),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPResult(LDAPProtocolResponse, BERSequence):
    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPResult":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPBindRequest(fallback=berdecoder)
        )
        if not (3 <= len(vals) <= 4):
            raise ValueError

        resultCode = validate_ber(vals[0], BEREnumerated)
        matchedDN = validate_ber(vals[1], BEROctetString)
        errorMessage = validate_ber(vals[2], BEROctetString)
        referral = None
        # if (l[3:] and isinstance(l[3], LDAPReferral)):
        # TODO support referrals
        # self.referral=self.data[0]

        r = klass(
            resultCode=resultCode.value,
            matchedDN=matchedDN.value,
            errorMessage=errorMessage.value,
            referral=referral,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int = None,
        matchedDN: bytes = None,
        errorMessage: bytes = None,
        referral=None,
        serverSaslCreds: bytes = None,
        tag=None,
    ):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, value=[], tag=tag)
        assert resultCode is not None
        self.resultCode = resultCode
        if matchedDN is None:
            matchedDN = ""
        self.matchedDN = matchedDN
        if errorMessage is None:
            errorMessage = ""
        self.errorMessage = errorMessage
        self.referral = referral
        self.serverSaslCreds = serverSaslCreds

    def toWire(self) -> bytes:
        assert self.referral is None  # TODO
        if self.serverSaslCreds:
            return BERSequence(
                [
                    BEREnumerated(self.resultCode),
                    BEROctetString(self.matchedDN),
                    BEROctetString(self.errorMessage),
                    LDAPBindResponse_serverSaslCreds(self.serverSaslCreds),
                ],
                tag=self.tag,
            ).toWire()
        else:
            return BERSequence(
                [
                    BEREnumerated(self.resultCode),
                    BEROctetString(self.matchedDN),
                    BEROctetString(self.errorMessage),
                ],
                tag=self.tag,
            ).toWire()

    def __repr__(self):
        l = []
        l.append("resultCode=%r" % self.resultCode)
        if self.matchedDN:
            l.append("matchedDN=%r" % self.matchedDN)
        if self.errorMessage:
            l.append("errorMessage=%r" % self.errorMessage)
        if self.referral:
            l.append("referral=%r" % self.referral)
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBindResponse_serverSaslCreds(BEROctetString):
    tag = CLASS_CONTEXT | 0x07

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % self.value
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                self.value,
                self.tag,
            )


class LDAPBERDecoderContext_BindResponse(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPBindResponse_serverSaslCreds.tag: LDAPBindResponse_serverSaslCreds,
    }


class LDAPBindResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x01

    resultCode: int = None  # type: ignore[assignment]
    matchedDN: bytes = None  # type: ignore[assignment]
    errorMessage: bytes = None  # type: ignore[assignment]
    referral = None
    serverSaslCreds: bytes = None  # type: ignore[assignment]

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPBindResponse":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_BindResponse(fallback=berdecoder)
        )

        if not (3 <= len(vals) <= 4):
            raise ValueError

        resultCode = validate_ber(vals[0], BEREnumerated)
        matchedDN = validate_ber(vals[1], BEROctetString)
        errorMessage = validate_ber(vals[2], BEROctetString)
        if len(vals) > 3 and isinstance(vals[3], LDAPBindResponse_serverSaslCreds):
            serverSaslCreds = validate_ber(vals[3], LDAPBindResponse_serverSaslCreds)
            serverSaslCreds_value = serverSaslCreds.value
        else:
            serverSaslCreds_value = None

        referral = None
        # if (l[3:] and isinstance(l[3], LDAPReferral)):
        # TODO support referrals
        # self.referral=self.data[0]

        r = klass(
            resultCode=resultCode.value,
            matchedDN=matchedDN.value,
            errorMessage=errorMessage.value,
            referral=referral,
            serverSaslCreds=serverSaslCreds_value,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int = None,
        matchedDN: bytes = None,
        errorMessage: bytes = None,
        referral=None,
        serverSaslCreds: bytes = None,
        tag: int = None,
    ):
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            # TODO why is tag not passed?
            tag=None,
        )

    def __repr__(self):
        return LDAPResult.__repr__(self)


class LDAPUnbindRequest(LDAPProtocolRequest, BERNull):
    tag = CLASS_APPLICATION | 0x02
    needs_answer = 0

    def __init__(self, *args, **kwargs):
        LDAPProtocolRequest.__init__(self)
        BERNull.__init__(self, *args, **kwargs)

    def toWire(self) -> bytes:
        return BERNull.toWire(self)


class LDAPAttributeDescription(BEROctetString):
    pass


class LDAPAttributeValueAssertion(BERSequence):
    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPAttributeValueAssertion":
        vals = berDecodeMultiple(content, berdecoder)
        if len(vals) != 2:
            raise ValueError
        attributeDesc = validate_ber(vals[0], BEROctetString)
        assertionValue = validate_ber(vals[1], BEROctetString)

        r = klass(attributeDesc=attributeDesc, assertionValue=assertionValue, tag=tag)
        return r

    def __init__(
        self,
        attributeDesc: BEROctetString = None,
        assertionValue: BEROctetString = None,
        tag: int = None,
        escaper: EscaperCallable = escape,
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert attributeDesc is not None
        self.attributeDesc = attributeDesc
        self.assertionValue = assertionValue
        self.escaper = escaper

    def toWire(self) -> bytes:
        return BERSequence(
            [self.attributeDesc, self.assertionValue], tag=self.tag
        ).toWire()

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return (
                self.__class__.__name__
                + "(attributeDesc={}, assertionValue={})".format(
                    repr(self.attributeDesc),
                    repr(self.assertionValue),
                )
            )
        else:
            return (
                self.__class__.__name__
                + "(attributeDesc=%s, assertionValue=%s, tag=%d)"
                % (repr(self.attributeDesc), repr(self.assertionValue), self.tag)
            )


# TODO can we unify this with LDAPFilter?
class AbstractLDAPFilter(BERBase, metaclass=abc.ABCMeta):
    pass


class LDAPFilter(BERStructured, AbstractLDAPFilter, metaclass=abc.ABCMeta):
    def __init__(self, tag=None):
        BERStructured.__init__(self, tag=tag)


class LDAPFilterSet(BERSet, AbstractLDAPFilter):
    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPFilterSet":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter(fallback=berdecoder)
        )
        r = klass(vals, tag=tag)
        return r

    def __eq__(self, rhs):
        # Fast paths
        if self is rhs:
            return True
        elif len(self) != len(rhs):
            return False

        return sorted(self, key=lambda x: x.toWire()) == sorted(
            rhs, key=lambda x: x.toWire()
        )


class LDAPFilter_and(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x00

    def asText(self) -> str:
        return "(&" + "".join([x.asText() for x in self]) + ")"


class LDAPFilter_or(LDAPFilterSet):
    tag = CLASS_CONTEXT | 0x01

    def asText(self) -> str:
        return "(|" + "".join([x.asText() for x in self]) + ")"


class LDAPFilter_not(LDAPFilter):
    tag = CLASS_CONTEXT | 0x02

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPFilter_not":
        val, bytes_ = berDecodeObject(
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
            content,
        )
        if bytes_ != len(content):
            raise ValueError
        value = validate_ber(val, AbstractLDAPFilter)

        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value: AbstractLDAPFilter, tag: int = tag):
        LDAPFilter.__init__(self, tag=tag)
        if value is None:
            raise ValueError
        self.value = value

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )

    def toWire(self) -> bytes:
        value = to_bytes(self.value)
        return bytes((self.identification(),)) + int2berlen(len(value)) + value

    def asText(self) -> str:
        return "(!" + self.value.asText() + ")"


class LDAPFilter_equalityMatch(LDAPAttributeValueAssertion, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x03

    def asText(self) -> str:
        return (
            "("
            + self.attributeDesc.value
            + "="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPFilter_substrings_initial(LDAPString, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x00

    def asText(self) -> str:
        return self.escaper(self.value)


class LDAPFilter_substrings_any(LDAPString, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x01

    def asText(self) -> str:
        return self.escaper(self.value)


class LDAPFilter_substrings_final(LDAPString, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x02

    def asText(self) -> str:
        return self.escaper(self.value)


class LDAPBERDecoderContext_Filter_substrings(BERDecoderContext):
    Identities: Mapping[int, Type[LDAPString]] = {
        LDAPFilter_substrings_initial.tag: LDAPFilter_substrings_initial,
        LDAPFilter_substrings_any.tag: LDAPFilter_substrings_any,
        LDAPFilter_substrings_final.tag: LDAPFilter_substrings_final,
    }


class LDAPFilter_substrings(BERSequence, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x04

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPFilter_substrings":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_Filter_substrings(fallback=berdecoder)
        )
        if len(vals) != 2:
            raise ValueError
        type_ = validate_ber(vals[0], BEROctetString)
        raw_substrings = validate_ber(vals[1], BERSequence)
        if len(raw_substrings) == 0:
            raise ValueError
        substrings = [validate_ber(sub, LDAPString) for sub in raw_substrings]

        r = klass(type=type_.value, substrings=substrings, tag=tag)
        return r

    def __init__(
        self, type: bytes = None, substrings: List[LDAPString] = None, tag: int = None
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        if type is None:
            raise ValueError
        if substrings is None:
            raise ValueError
        self.type = type
        self.substrings = substrings

    def toWire(self) -> bytes:
        return BERSequence(
            [LDAPString(self.type), BERSequence(self.substrings)], tag=self.tag
        ).toWire()

    def __repr__(self):
        tp = self.type
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(type={}, substrings={})".format(
                repr(tp),
                repr(self.substrings),
            )
        else:
            return self.__class__.__name__ + "(type=%s, substrings=%s, tag=%d)" % (
                repr(tp),
                repr(self.substrings),
                self.tag,
            )

    def asText(self) -> str:
        initial = None
        final = None
        any = []

        for s in self.substrings:
            assert s is not None
            if isinstance(s, LDAPFilter_substrings_initial):
                assert initial is None
                assert not any
                assert final is None
                initial = s.asText()
            elif isinstance(s, LDAPFilter_substrings_final):
                assert final is None
                final = s.asText()
            elif isinstance(s, LDAPFilter_substrings_any):
                assert final is None
                any.append(s.asText())
            else:
                raise NotImplementedError("TODO: Filter type not supported %r" % s)

        if initial is None:
            initial = ""
        if final is None:
            final = ""

        return "(" + self.type + "=" + "*".join([initial] + any + [final]) + ")"


class LDAPFilter_greaterOrEqual(LDAPAttributeValueAssertion, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x05

    def asText(self) -> str:
        return (
            "("
            + self.attributeDesc.value
            + ">="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPFilter_lessOrEqual(LDAPAttributeValueAssertion, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x06

    def asText(self) -> str:
        return (
            "("
            + self.attributeDesc.value
            + "<="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPFilter_present(LDAPAttributeDescription, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x07

    def asText(self) -> str:
        return "(%s=*)" % self.value


class LDAPFilter_approxMatch(LDAPAttributeValueAssertion, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x08

    def asText(self) -> str:
        return (
            "("
            + self.attributeDesc.value
            + "~="
            + self.escaper(self.assertionValue.value)
            + ")"
        )


class LDAPMatchingRuleId(LDAPString):
    pass


class LDAPAssertionValue(BEROctetString):
    pass


class LDAPMatchingRuleAssertion_matchingRule(LDAPMatchingRuleId):
    tag = CLASS_CONTEXT | 0x01


class LDAPMatchingRuleAssertion_type(LDAPAttributeDescription):
    tag = CLASS_CONTEXT | 0x02


class LDAPMatchingRuleAssertion_matchValue(LDAPAssertionValue):
    tag = CLASS_CONTEXT | 0x03


class LDAPMatchingRuleAssertion_dnAttributes(BERBoolean):
    tag = CLASS_CONTEXT | 0x04


class LDAPBERDecoderContext_MatchingRuleAssertion(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPMatchingRuleAssertion_matchingRule.tag: LDAPMatchingRuleAssertion_matchingRule,
        LDAPMatchingRuleAssertion_type.tag: LDAPMatchingRuleAssertion_type,
        LDAPMatchingRuleAssertion_matchValue.tag: LDAPMatchingRuleAssertion_matchValue,
        LDAPMatchingRuleAssertion_dnAttributes.tag: LDAPMatchingRuleAssertion_dnAttributes,
    }


class LDAPMatchingRuleAssertion(BERSequence):
    # TODO this class stores its attributes as LDAP* objects. Maybe unify this with the
    #  other classes (in any direction)?
    matchingRule: LDAPMatchingRuleAssertion_matchingRule = None  # type: ignore[assignment]
    type: LDAPMatchingRuleAssertion_type = None  # type: ignore[assignment]
    matchValue: LDAPMatchingRuleAssertion_matchValue = None  # type: ignore[assignment]
    dnAttributes: Optional[LDAPMatchingRuleAssertion_dnAttributes] = None
    escaper: EscaperCallable

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPMatchingRuleAssertion":
        matchingRule = None
        atype = None
        matchValue = None
        dnAttributes = None
        vals = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_MatchingRuleAssertion(
                fallback=berdecoder, inherit=berdecoder
            ),
        )
        if not (1 <= len(vals) <= 4):
            raise ValueError
        if isinstance(vals[0], LDAPMatchingRuleAssertion_matchingRule):
            matchingRule = validate_ber(vals[0], LDAPMatchingRuleAssertion_matchingRule)
        if len(vals) >= 2 and isinstance(vals[1], LDAPMatchingRuleAssertion_type):
            atype = validate_ber(vals[1], LDAPMatchingRuleAssertion_type)
        if len(vals) >= 3 and isinstance(vals[2], LDAPMatchingRuleAssertion_matchValue):
            matchValue = validate_ber(vals[2], LDAPMatchingRuleAssertion_matchValue)
        if len(vals) == 4 and isinstance(
            vals[3], LDAPMatchingRuleAssertion_dnAttributes
        ):
            dnAttributes = validate_ber(vals[3], LDAPMatchingRuleAssertion_dnAttributes)
        if matchingRule is None:
            raise ValueError
        if not dnAttributes:
            dnAttributes = None
        r = klass(
            matchingRule=matchingRule,
            type=atype,
            matchValue=matchValue,
            dnAttributes=dnAttributes,
            tag=tag,
        )

        return r

    def __init__(
        self,
        matchingRule: Union[bytes, LDAPMatchingRuleAssertion_matchingRule] = None,
        type: Union[bytes, LDAPMatchingRuleAssertion_type] = None,
        matchValue: Union[bytes, LDAPMatchingRuleAssertion_matchValue] = None,
        dnAttributes: Union[bool, LDAPMatchingRuleAssertion_dnAttributes] = None,
        tag: int = None,
        escaper: EscaperCallable = escape,
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert matchValue is not None
        if isinstance(matchingRule, (bytes, str)):
            matchingRule = LDAPMatchingRuleAssertion_matchingRule(matchingRule)

        if isinstance(type, (bytes, str)):
            type = LDAPMatchingRuleAssertion_type(type)

        if isinstance(matchValue, (bytes, str)):
            matchValue = LDAPMatchingRuleAssertion_matchValue(matchValue)

        if isinstance(dnAttributes, bool):
            dnAttributes = LDAPMatchingRuleAssertion_dnAttributes(dnAttributes)

        self.matchingRule = matchingRule
        self.type = type
        self.matchValue = matchValue
        self.dnAttributes = dnAttributes
        if not self.dnAttributes:
            self.dnAttributes = None
        self.escaper = escaper

    def toWire(self) -> bytes:
        return BERSequence(
            filter(
                lambda x: x is not None,
                [self.matchingRule, self.type, self.matchValue, self.dnAttributes],
            ),
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        l = []
        l.append("matchingRule=%s" % repr(self.matchingRule))
        l.append("type=%s" % repr(self.type))
        l.append("matchValue=%s" % repr(self.matchValue))
        l.append("dnAttributes=%s" % repr(self.dnAttributes))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPFilter_extensibleMatch(LDAPMatchingRuleAssertion, AbstractLDAPFilter):
    tag = CLASS_CONTEXT | 0x09

    def asText(self) -> str:
        return (
            "("
            + (self.type.value if self.type else "")
            + (":dn" if self.dnAttributes and self.dnAttributes.value else "")
            + ((":" + self.matchingRule.value) if self.matchingRule else "")
            + ":="
            + self.escaper(self.matchValue.value)
            + ")"
        )


class LDAPBERDecoderContext_Filter(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPFilter_and.tag: LDAPFilter_and,
        LDAPFilter_or.tag: LDAPFilter_or,
        LDAPFilter_not.tag: LDAPFilter_not,
        LDAPFilter_equalityMatch.tag: LDAPFilter_equalityMatch,
        LDAPFilter_substrings.tag: LDAPFilter_substrings,
        LDAPFilter_greaterOrEqual.tag: LDAPFilter_greaterOrEqual,
        LDAPFilter_lessOrEqual.tag: LDAPFilter_lessOrEqual,
        LDAPFilter_present.tag: LDAPFilter_present,
        LDAPFilter_approxMatch.tag: LDAPFilter_approxMatch,
        LDAPFilter_extensibleMatch.tag: LDAPFilter_extensibleMatch,
    }


LDAP_SCOPE_baseObject = 0
LDAP_SCOPE_singleLevel = 1
LDAP_SCOPE_wholeSubtree = 2

LDAP_DEREF_neverDerefAliases = 0
LDAP_DEREF_derefInSearching = 1
LDAP_DEREF_derefFindingBaseObj = 2
LDAP_DEREF_derefAlways = 3

LDAPFilterMatchAll = LDAPFilter_present("objectClass")


class LDAPSearchRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x03

    baseObject = ""
    scope = LDAP_SCOPE_wholeSubtree
    derefAliases = LDAP_DEREF_neverDerefAliases
    sizeLimit = 0
    timeLimit = 0
    # TODO change to bool?
    typesOnly = 0
    filter = LDAPFilterMatchAll
    attributes: List[bytes] = []  # TODO AttributeDescriptionList

    # TODO decode

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPSearchRequest":
        vals = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )
        if len(vals) != 8:
            raise ValueError

        baseObject = validate_ber(vals[0], BEROctetString)
        scope = validate_ber(vals[1], BEREnumerated)
        derefAliases = validate_ber(vals[2], BEREnumerated)
        sizeLimit = validate_ber(vals[3], BERInteger)
        timeLimit = validate_ber(vals[4], BERInteger)
        typesOnly = validate_ber(vals[5], BERBoolean)
        filter_ = validate_ber(vals[6], AbstractLDAPFilter)
        attributes = validate_ber(vals[7], BERSequence)

        r = klass(
            baseObject=baseObject.value,
            scope=scope.value,
            derefAliases=derefAliases.value,
            sizeLimit=sizeLimit.value,
            timeLimit=timeLimit.value,
            typesOnly=typesOnly.value,
            filter=filter_,
            attributes=[x.value for x in attributes],
            tag=tag,
        )
        return r

    def __init__(
        self,
        baseObject: bytes = None,
        scope: int = None,
        derefAliases: int = None,
        sizeLimit: int = None,
        timeLimit: int = None,
        typesOnly: int = None,
        filter: AbstractLDAPFilter = None,
        attributes: List[bytes] = None,
        tag: int = None,
    ):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)

        if baseObject is not None:
            self.baseObject = baseObject
        if scope is not None:
            self.scope = scope
        if derefAliases is not None:
            self.derefAliases = derefAliases
        if sizeLimit is not None:
            self.sizeLimit = sizeLimit
        if timeLimit is not None:
            self.timeLimit = timeLimit
        if typesOnly is not None:
            self.typesOnly = typesOnly
        if filter is not None:
            self.filter = filter
        if attributes is not None:
            self.attributes = attributes

    def toWire(self) -> bytes:
        return BERSequence(
            [
                BEROctetString(self.baseObject),
                BEREnumerated(self.scope),
                BEREnumerated(self.derefAliases),
                BERInteger(self.sizeLimit),
                BERInteger(self.timeLimit),
                BERBoolean(self.typesOnly),
                self.filter,
                BERSequenceOf(map(BEROctetString, self.attributes)),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        base = self.baseObject
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
            )

        else:
            return self.__class__.__name__ + (
                "(baseObject=%s, scope=%s, derefAliases=%s, "
                + "sizeLimit=%s, timeLimit=%s, typesOnly=%s, "
                "filter=%s, attributes=%s, tag=%d)"
            ) % (
                repr(base),
                self.scope,
                self.derefAliases,
                self.sizeLimit,
                self.timeLimit,
                self.typesOnly,
                repr(self.filter),
                self.attributes,
                self.tag,
            )


class LDAPSearchResultEntry(LDAPProtocolResponse, BERSequence):
    tag = CLASS_APPLICATION | 0x04
    objectName: bytes
    attributes: List[Tuple[bytes, List[bytes]]]

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPSearchResultEntry":
        vals = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Filter(fallback=berdecoder, inherit=berdecoder),
        )

        objectName = validate_ber(vals[0], BEROctetString)
        raw_attributes = validate_ber(vals[1], BERSequence)
        attributes = []
        for raw_attribute, raw_val in raw_attributes.data:
            attribute = validate_ber(raw_attribute, BEROctetString)
            raw_values = validate_ber(raw_val, BERSet)
            values = [validate_ber(val, BEROctetString).value for val in raw_values]
            attributes.append((attribute.value, values))
        r = klass(objectName=objectName.value, attributes=attributes, tag=tag)
        return r

    def __init__(
        self,
        objectName: bytes,
        attributes: List[Tuple[bytes, List[bytes]]],
        tag: int = None,
    ):
        LDAPProtocolResponse.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert objectName is not None
        assert attributes is not None
        self.objectName = objectName
        self.attributes = attributes

    def toWire(self) -> bytes:
        return BERSequence(
            [
                BEROctetString(self.objectName),
                BERSequence(
                    [
                        BERSequence(
                            [
                                BEROctetString(attr_li[0]),
                                BERSet([BEROctetString(x) for x in attr_li[1]]),
                            ]
                        )
                        for attr_li in self.attributes
                    ]
                ),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        name = self.objectName
        attributes = [(key, [v for v in value]) for (key, value) in self.attributes]
        return "{}(objectName={}, attributes={}{})".format(
            self.__class__.__name__,
            repr(name),
            repr(attributes),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPSearchResultDone(LDAPResult):
    tag = CLASS_APPLICATION | 0x05


class LDAPControls(BERSequence):
    tag = CLASS_CONTEXT | 0x00

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPControls":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPControls(inherit=berdecoder)
        )
        controls = [validate_ber(val, LDAPControl) for val in vals]

        r = klass(controls, tag=tag)
        return r


class LDAPControl(BERSequence):
    criticality: bool = None  # type: ignore[assignment]
    controlValue: bytes = None  # type: ignore[assignment]

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPControl":
        vals = berDecodeMultiple(content, berdecoder)

        if not (1 <= len(vals) <= 3):
            raise ValueError

        controlType = validate_ber(vals[0], BEROctetString)
        criticality = None
        controlValue = None

        if len(vals) == 2:
            if isinstance(vals[1], BERBoolean):
                criticality = validate_ber(vals[1], BERBoolean).value
            elif isinstance(vals[1], BEROctetString):
                controlValue = validate_ber(vals[1], BEROctetString).value
        elif len(vals) == 3:
            criticality = validate_ber(vals[1], BERBoolean).value
            controlValue = validate_ber(vals[2], BEROctetString).value

        r = klass(
            controlType=controlType.value,
            tag=tag,
            criticality=criticality,
            controlValue=controlValue,
        )
        return r

    def __init__(
        self,
        controlType: bytes,
        criticality: bool = None,
        controlValue: bytes = None,
        id=None,
        tag: int = None,
    ):
        BERSequence.__init__(self, value=[], tag=tag)
        assert controlType is not None
        self.controlType = controlType
        self.criticality = criticality
        self.controlValue = controlValue

    def toWire(self) -> bytes:
        self.data = [LDAPOID(self.controlType)]
        if self.criticality is not None:
            self.data.append(BERBoolean(self.criticality))
        if self.controlValue is not None:
            self.data.append(BEROctetString(self.controlValue))
        return BERSequence.toWire(self)


class LDAPBERDecoderContext_LDAPControls(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPControl.tag: LDAPControl,
    }


class LDAPBERDecoderContext_LDAPMessage(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPControls.tag: LDAPControls,
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
    }


class LDAPBERDecoderContext_TopLevel(BERDecoderContext):
    Identities: Mapping[int, Type[LDAPMessage]] = {
        BERSequence.tag: LDAPMessage,
    }


class LDAPModifyRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x06
    object: bytes = None  # type: ignore[assignment]
    modification: List[BERBase] = None  # type: ignore[assignment]

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPModifyRequest":
        vals = berDecodeMultiple(content, berdecoder)

        if len(vals) != 2:
            raise ValueError

        object = validate_ber(vals[0], BEROctetString)
        modification = validate_ber(vals[1], BERSequence)

        r = klass(object=object.value, modification=modification.data, tag=tag)
        return r

    def __init__(
        self, object: bytes = None, modification: List[BERBase] = None, tag: int = None
    ):
        """
        Initialize the object

        Example usage::

                l = LDAPModifyRequest(
                    object='cn=foo,dc=example,dc=com',
                    modification=[

                      BERSequence([
                        BEREnumerated(0),
                        BERSequence([
                          LDAPAttributeDescription('attr1'),
                          BERSet([
                            LDAPString('value1'),
                            LDAPString('value2'),
                            ]),
                          ]),
                        ]),

                      BERSequence([
                        BEREnumerated(1),
                        BERSequence([
                          LDAPAttributeDescription('attr2'),
                          ]),
                        ]),

                    ])

        But more likely you just want to say::

                mod = delta.ModifyOp('cn=foo,dc=example,dc=com',
                    [delta.Add('attr1', ['value1', 'value2']),
                     delta.Delete('attr1', ['value1', 'value2'])])
                l = mod.asLDAP()
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.object = object
        self.modification = modification

    def toWire(self) -> bytes:
        l = [LDAPString(self.object)]
        if self.modification is not None:
            l.append(BERSequence(self.modification))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self):
        name = self.object
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(object={}, modification={})".format(
                repr(name),
                repr(self.modification),
            )
        else:
            return self.__class__.__name__ + "(object=%s, modification=%s, tag=%d)" % (
                repr(name),
                repr(self.modification),
                self.tag,
            )


class LDAPModifyResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x07


class LDAPAddRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 0x08
    entry: bytes
    attributes: BERSequence

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPAddRequest":
        vals = berDecodeMultiple(content, berdecoder)

        entry = validate_ber(vals[0], BEROctetString)
        attributes = validate_ber(vals[1], BERSequence)
        # TODO extend validation and casting

        r = klass(entry=entry.value, attributes=attributes, tag=tag)
        return r

    def __init__(
        self, entry: bytes = None, attributes: BERSequence = None, tag: int = None
    ):
        """
        Initialize the object

        Example usage::

                l=LDAPAddRequest(entry='cn=foo,dc=example,dc=com',
                        attributes=[(LDAPAttributeDescription("attrFoo"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             (LDAPAttributeDescription("attrBar"),
                             BERSet(value=(
                                 LDAPAttributeValue("value1"),
                                 LDAPAttributeValue("value2"),
                             ))),
                             ])"""

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        self.entry = entry
        self.attributes = attributes

    def toWire(self) -> bytes:
        return BERSequence(
            [
                LDAPString(self.entry),
                BERSequence(map(BERSequence, self.attributes)),
            ],
            tag=self.tag,
        ).toWire()

    def __repr__(self):
        entry = self.entry
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry={}, attributes={})".format(
                repr(entry),
                repr(self.attributes),
            )
        else:
            return self.__class__.__name__ + "(entry=%s, attributes=%s, tag=%d)" % (
                repr(entry),
                repr(self.attributes),
                self.tag,
            )


class LDAPAddResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x09


class LDAPDelRequest(LDAPProtocolRequest, LDAPString):
    tag = CLASS_APPLICATION | 0x0A

    # TODO ?
    def __init__(self, value=None, entry=None, tag=None):
        """
        Initialize the object

        l=LDAPDelRequest(entry='cn=foo,dc=example,dc=com')
        """
        if entry is None and value is not None:
            entry = value
        LDAPProtocolRequest.__init__(self)
        LDAPString.__init__(self, value=entry, tag=tag)

    def toWire(self) -> bytes:
        return LDAPString.toWire(self)

    def __repr__(self):
        entry = self.value
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(entry=%s)" % repr(entry)
        else:
            return self.__class__.__name__ + "(entry=%s, tag=%d)" % (
                repr(entry),
                self.tag,
            )


class LDAPDelResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x0B


class LDAPModifyDNResponse_newSuperior(LDAPString):
    tag = CLASS_CONTEXT | 0x00


class LDAPBERDecoderContext_ModifyDNRequest(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPModifyDNResponse_newSuperior.tag: LDAPModifyDNResponse_newSuperior,
    }


class LDAPModifyDNRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 12

    entry: bytes = None  # type: ignore[assignment]
    newrdn: bytes = None  # type: ignore[assignment]
    deleteoldrdn: bool = None  # type: ignore[assignment]
    newSuperior: Optional[bytes] = None

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPModifyDNRequest":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_ModifyDNRequest(fallback=berdecoder)
        )
        if not (3 <= len(vals) <= 4):
            raise ValueError

        entry = validate_ber(vals[0], BEROctetString)
        newrdn = validate_ber(vals[1], BEROctetString)
        deleteoldrdn = validate_ber(vals[2], BERBoolean)
        if len(vals) == 4:
            newSuperior = to_bytes(validate_ber(vals[3], BEROctetString).value)
        else:
            newSuperior = None

        # TODO the to_bytes conversion should be idempotent
        r = klass(
            entry=to_bytes(entry.value),
            newrdn=to_bytes(newrdn.value),
            deleteoldrdn=deleteoldrdn.value,
            tag=tag,
            newSuperior=newSuperior,
        )
        return r

    def __init__(
        self,
        entry: bytes,
        newrdn: bytes,
        deleteoldrdn: bool,
        newSuperior: bytes = None,
        tag: int = None,
    ):
        """
        Initialize the object

        Example usage::

                l=LDAPModifyDNRequest(entry='cn=foo,dc=example,dc=com',
                                      newrdn='someAttr=value',
                                      deleteoldrdn=0)
        """

        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert newrdn is not None
        assert deleteoldrdn is not None
        self.entry = entry
        self.newrdn = newrdn
        self.deleteoldrdn = deleteoldrdn
        self.newSuperior = newSuperior

    def toWire(self) -> bytes:
        l = [
            LDAPString(self.entry),
            LDAPString(self.newrdn),
            BERBoolean(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append(LDAPString(self.newSuperior, tag=CLASS_CONTEXT | 0))
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self):
        l = [
            "entry=%s" % repr(self.entry),
            "newrdn=%s" % repr(self.newrdn),
            "deleteoldrdn=%s" % repr(self.deleteoldrdn),
        ]
        if self.newSuperior is not None:
            l.append("newSuperior=%s" % repr(self.newSuperior))
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPModifyDNResponse(LDAPResult):
    tag = CLASS_APPLICATION | 13


class LDAPBERDecoderContext_Compare(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        BERSequence.tag: LDAPAttributeValueAssertion
    }


class LDAPCompareRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 14

    entry: bytes = None  # type: ignore[assignment]
    ava: LDAPAttributeValueAssertion = None  # type: ignore[assignment]

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPCompareRequest":
        vals = berDecodeMultiple(
            content,
            LDAPBERDecoderContext_Compare(fallback=berdecoder, inherit=berdecoder),
        )
        if len(vals) != 2:
            raise ValueError

        entry = validate_ber(vals[0], BEROctetString)
        ava = validate_ber(vals[1], LDAPAttributeValueAssertion)

        r = klass(entry=entry.value, ava=ava, tag=tag)

        return r

    def __init__(self, entry: bytes, ava: LDAPAttributeValueAssertion, tag: int = None):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert entry is not None
        assert ava is not None
        self.entry = entry
        self.ava = ava

    def toWire(self) -> bytes:
        l = [LDAPString(self.entry), self.ava]
        return BERSequence(l, tag=self.tag).toWire()

    def __repr__(self):
        l = [
            f"entry={repr(self.entry)}",
            f"ava={repr(self.ava)}",
        ]
        return "{}({})".format(self.__class__.__name__, ", ".join(l))


class LDAPCompareResponse(LDAPResult):
    tag = CLASS_APPLICATION | 15


class LDAPAbandonRequest(LDAPProtocolRequest, LDAPInteger):
    tag = CLASS_APPLICATION | 0x10
    needs_answer = 0

    def __init__(self, value=None, id=None, tag=None):
        """
        Initialize the object

        l=LDAPAbandonRequest(id=1)
        """
        if id is None and value is not None:
            id = value
        LDAPProtocolRequest.__init__(self)
        LDAPInteger.__init__(self, value=id, tag=tag)

    def toWire(self) -> bytes:
        return LDAPInteger.toWire(self)

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(id=%s)" % repr(self.value)
        else:
            return self.__class__.__name__ + "(id=%s, tag=%d)" % (
                repr(self.value),
                self.tag,
            )


class LDAPOID(BEROctetString):
    pass


class LDAPResponseName(LDAPOID):
    tag = CLASS_CONTEXT | 10


class LDAPResponse(BEROctetString):
    tag = CLASS_CONTEXT | 11


class LDAPBERDecoderContext_LDAPExtendedRequest(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        CLASS_CONTEXT | 0x00: BEROctetString,
        CLASS_CONTEXT | 0x01: BEROctetString,
    }


class LDAPExtendedRequest(LDAPProtocolRequest, BERSequence):
    tag = CLASS_APPLICATION | 23

    requestName: bytes = None  # type: ignore[assignment]
    requestValue: Optional[bytes] = None

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPExtendedRequest":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedRequest(fallback=berdecoder)
        )
        if not (1 <= len(vals) <= 2):
            raise ValueError

        requestName = validate_ber(vals[0], BEROctetString)
        if len(vals) == 2:
            requestValue = validate_ber(vals[1], BEROctetString).value
        else:
            requestValue = None

        r = klass(requestName=requestName.value, requestValue=requestValue, tag=tag)
        return r

    def __init__(
        self, requestName: bytes = None, requestValue: bytes = None, tag: int = None
    ):
        LDAPProtocolRequest.__init__(self)
        BERSequence.__init__(self, [], tag=tag)
        assert requestName is not None
        assert isinstance(requestName, (bytes, str))
        assert requestValue is None or isinstance(requestValue, (bytes, str))
        self.requestName = requestName
        self.requestValue = requestValue

    def toWire(self) -> bytes:
        l = [LDAPOID(self.requestName, tag=CLASS_CONTEXT | 0)]
        if self.requestValue is not None:
            value = to_bytes(self.requestValue)
            l.append(BEROctetString(value, tag=CLASS_CONTEXT | 1))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPPasswordModifyRequest_userIdentity(BEROctetString):
    tag = CLASS_CONTEXT | 0


class LDAPPasswordModifyRequest_passwd(BEROctetString):
    def __repr__(self):
        value = "*" * len(self.value)
        return "{}(value={}{})".format(
            self.__class__.__name__,
            repr(value),
            f", tag={self.tag}" if self.tag != self.__class__.tag else "",
        )


class LDAPPasswordModifyRequest_oldPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 1


class LDAPPasswordModifyRequest_newPasswd(LDAPPasswordModifyRequest_passwd):
    tag = CLASS_CONTEXT | 2


class LDAPBERDecoderContext_LDAPPasswordModifyRequest(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPPasswordModifyRequest_userIdentity.tag: LDAPPasswordModifyRequest_userIdentity,
        LDAPPasswordModifyRequest_oldPasswd.tag: LDAPPasswordModifyRequest_oldPasswd,
        LDAPPasswordModifyRequest_newPasswd.tag: LDAPPasswordModifyRequest_newPasswd,
    }


class LDAPPasswordModifyRequest(LDAPExtendedRequest):
    oid = b"1.3.6.1.4.1.4203.1.11.1"

    # TODO how does this work?
    def __init__(
        self,
        requestName=None,
        userIdentity=None,
        oldPasswd=None,
        newPasswd=None,
        tag=None,
    ):
        assert (
            requestName is None or requestName == self.oid
        ), "{} requestName was {} instead of {}".format(
            self.__class__.__name__,
            requestName,
            self.oid,
        )
        # TODO genPasswd

        l = []
        self.userIdentity = None
        if userIdentity is not None:
            self.userIdentity = LDAPPasswordModifyRequest_userIdentity(userIdentity)
            l.append(self.userIdentity)

        self.oldPasswd = None
        if oldPasswd is not None:
            self.oldPasswd = LDAPPasswordModifyRequest_oldPasswd(oldPasswd)
            l.append(self.oldPasswd)

        self.newPasswd = None
        if newPasswd is not None:
            self.newPasswd = LDAPPasswordModifyRequest_newPasswd(newPasswd)
            l.append(self.newPasswd)

        LDAPExtendedRequest.__init__(
            self, requestName=self.oid, requestValue=BERSequence(l).toWire(), tag=tag
        )

    def __repr__(self):
        l = []
        if self.userIdentity is not None:
            l.append(f"userIdentity={repr(self.userIdentity)}")
        if self.oldPasswd is not None:
            l.append(f"oldPasswd={repr(self.oldPasswd)}")
        if self.newPasswd is not None:
            l.append(f"newPasswd={repr(self.newPasswd)}")
        if self.tag != self.__class__.tag:
            l.append("tag=%d" % self.tag)
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBERDecoderContext_LDAPExtendedResponse(BERDecoderContext):
    Identities: Mapping[int, Type[BERBase]] = {
        LDAPResponseName.tag: LDAPResponseName,
        LDAPResponse.tag: LDAPResponse,
    }


class LDAPExtendedResponse(LDAPResult):
    tag = CLASS_APPLICATION | 0x18

    responseName: Optional[bytes] = None
    response: Optional[bytes] = None

    @classmethod
    def fromBER(
        klass, tag: int, content: bytes, berdecoder: BERDecoderContext = None
    ) -> "LDAPExtendedResponse":
        vals = berDecodeMultiple(
            content, LDAPBERDecoderContext_LDAPExtendedResponse(fallback=berdecoder)
        )

        if not (3 <= len(vals) <= 6):
            raise ValueError

        resultCode = validate_ber(vals[0], BEREnumerated)
        matchedDN = validate_ber(vals[1], BEROctetString)
        errorMessage = validate_ber(vals[2], BEROctetString)

        referral = None
        responseName = None
        response = None
        for obj in vals[3:]:
            if isinstance(obj, LDAPResponseName):
                responseName = validate_ber(obj, LDAPResponseName).value
            elif isinstance(obj, LDAPResponse):
                response = validate_ber(obj, LDAPResponse).value
            elif isinstance(obj, LDAPReferral):
                # TODO support referrals
                # self.referral=self.data[0]
                pass
            else:
                assert False

        r = klass(
            resultCode=resultCode.value,
            matchedDN=matchedDN.value,
            errorMessage=errorMessage.value,
            referral=referral,
            responseName=responseName,
            response=response,
            tag=tag,
        )
        return r

    def __init__(
        self,
        resultCode: int = None,
        matchedDN: bytes = None,
        errorMessage: bytes = None,
        referral=None,
        serverSaslCreds=None,
        responseName: Optional[bytes] = None,
        response: Optional[bytes] = None,
        tag: int = None,
    ):
        LDAPResult.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            tag=tag,
        )
        self.responseName = responseName
        self.response = response

    def toWire(self) -> bytes:
        assert self.referral is None  # TODO
        l = [
            BEREnumerated(self.resultCode),
            BEROctetString(self.matchedDN),
            BEROctetString(self.errorMessage),
            # TODO referral [3] Referral OPTIONAL
        ]
        if self.responseName is not None:
            l.append(LDAPOID(self.responseName, tag=CLASS_CONTEXT | 0x0A))
        if self.response is not None:
            l.append(BEROctetString(self.response, tag=CLASS_CONTEXT | 0x0B))
        return BERSequence(l, tag=self.tag).toWire()


class LDAPStartTLSRequest(LDAPExtendedRequest):
    """
    Request to start Transport Layer Security.
    See RFC 2830 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(self, requestName=None, tag=None):
        assert (
            requestName is None or requestName == self.oid
        ), "{} requestName was {} instead of {}".format(
            self.__class__.__name__,
            requestName,
            self.oid,
        )

        LDAPExtendedRequest.__init__(self, requestName=self.oid, tag=tag)

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append(f"tag={self.tag}")
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPStartTLSResponse(LDAPExtendedResponse):
    """
    Response to start Transport Layer Security.
    See RFC 4511 section 4.14.2 for details.
    """

    oid = b"1.3.6.1.4.1.1466.20037"

    def __init__(
        self,
        resultCode: int = None,
        matchedDN: bytes = None,
        errorMessage: bytes = None,
        referral=None,
        serverSaslCreds=None,
        responseName: Optional[bytes] = None,
        response: Optional[bytes] = None,
        tag: int = None,
    ):
        LDAPExtendedResponse.__init__(
            self,
            resultCode=resultCode,
            matchedDN=matchedDN,
            errorMessage=errorMessage,
            referral=referral,
            serverSaslCreds=serverSaslCreds,
            responseName=responseName,
            response=response,
            tag=tag,
        )

    def __repr__(self):
        l = []
        if self.tag != self.__class__.tag:
            l.append(f"tag={self.tag}")
        return self.__class__.__name__ + "(" + ", ".join(l) + ")"


class LDAPBERDecoderContext(BERDecoderContext):
    Identities: Mapping[int, Type[LDAPProtocolOp]] = {
        LDAPBindResponse.tag: LDAPBindResponse,
        LDAPBindRequest.tag: LDAPBindRequest,
        LDAPUnbindRequest.tag: LDAPUnbindRequest,
        LDAPSearchRequest.tag: LDAPSearchRequest,
        LDAPSearchResultEntry.tag: LDAPSearchResultEntry,
        LDAPSearchResultDone.tag: LDAPSearchResultDone,
        LDAPSearchResultReference.tag: LDAPSearchResultReference,
        LDAPReferral.tag: LDAPReferral,
        LDAPModifyRequest.tag: LDAPModifyRequest,
        LDAPModifyResponse.tag: LDAPModifyResponse,
        LDAPAddRequest.tag: LDAPAddRequest,
        LDAPAddResponse.tag: LDAPAddResponse,
        LDAPDelRequest.tag: LDAPDelRequest,
        LDAPDelResponse.tag: LDAPDelResponse,
        LDAPExtendedRequest.tag: LDAPExtendedRequest,
        LDAPExtendedResponse.tag: LDAPExtendedResponse,
        LDAPModifyDNRequest.tag: LDAPModifyDNRequest,
        LDAPModifyDNResponse.tag: LDAPModifyDNResponse,
        LDAPAbandonRequest.tag: LDAPAbandonRequest,
        LDAPCompareRequest.tag: LDAPCompareRequest,
        LDAPCompareResponse.tag: LDAPCompareResponse,
    }
