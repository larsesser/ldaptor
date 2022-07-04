"""LDAP protocol server"""
import asyncio
from asyncio.transports import Transport
from typing import Optional, Callable

from ldaptor import interfaces, delta
from ldaptor.entry import LdapEntry
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.pureldap import LDAPMessage, LDAPExtendedResponse
from ldaptor.protocols.ldap.ldaperrors import LDAPException, LDAPProtocolError
from ldaptor.protocols.ldap import distinguishedname, ldaperrors
from twisted.python import log
from twisted.internet import protocol, defer

ReplyCallback = Callable[[pureldap.LDAPProtocolResponse], None]


class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass


class BaseLdapServer(asyncio.Protocol):
    def __init__(self, root: LdapEntry, *, debug: bool = False):
        self.buffer = b""
        self.connected = False
        self.transport: Transport = None
        self.root = root
        self.debug = debug

    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
            inherit=pureldap.LDAPBERDecoderContext(
                fallback=pureber.BERDecoderContext()
            ),
        )
    )

    def connection_made(self, transport: Transport) -> None:
        self.connected = True
        assert isinstance(transport, Transport)
        self.transport = transport

    def connection_lost(self, exc: Exception | None) -> None:
        # TODO maybe handle the exception or proper close the connection
        self.connected = False
        self.transport.close()

    def data_received(self, data: bytes) -> None:
        self.buffer += data
        while 1:
            try:
                o, bytes = pureber.berDecodeObject(self.berdecoder, self.buffer)
            except pureber.BERExceptionInsufficientData:
                o, bytes = None, 0
            self.buffer = self.buffer[bytes:]
            if o is None:
                break
            # TODO this is some very obscure code path, related to the construction of
            #  the berdecoder object...
            assert isinstance(o, LDAPMessage)
            self.handle(o)

    def queue(self, msg_id: int, op: pureldap.LDAPProtocolResponse) -> None:
        if not self.connected:
            raise LDAPServerConnectionLostException()
        msg = pureldap.LDAPMessage(op, id=msg_id)
        if self.debug:
            log.msg("S->C %s" % repr(msg), debug=True)
        self.transport.write(msg.toWire())

    def unsolicitedNotification(self, msg):
        log.msg("Got unsolicited notification: %s" % repr(msg))

    def checkControls(self, controls: Optional[pureldap.LDAPControls]) -> None:
        if controls is not None:
            for controlType, criticality, controlValue in controls:
                if criticality:
                    raise ldaperrors.LDAPUnavailableCriticalExtension(
                        b"Unknown control %s" % controlType
                    )

    def handleUnknown(
        self,
        request: pureldap.LDAPProtocolRequest,
        controls: Optional[pureldap.LDAPControls],
        reply: ReplyCallback,
    ) -> None:
        log.msg("Unknown request: %r" % request)
        msg = pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage="Unknown request",
        )
        reply(msg)

    def failDefault(
        self, resultCode: int, errorMessage: str
    ) -> pureldap.LDAPProtocolResponse:
        return pureldap.LDAPExtendedResponse(
            resultCode=resultCode,
            responseName="1.3.6.1.4.1.1466.20036",
            errorMessage=errorMessage,
        )

    def handle(self, msg: LDAPMessage):
        assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            log.msg("S<-C %s" % repr(msg), debug=True)

        if msg.id == 0:
            self.unsolicitedNotification(msg.value)
        else:
            name = msg.value.__class__.__name__
            handler = getattr(self, "handle_" + name, self.handleUnknown)
            error_handler = getattr(self, "fail_" + name, self.failDefault)
            try:
                handler(
                    msg.value,
                    msg.controls,
                    lambda response: self.queue(msg.id, response),
                )
            except LDAPException as e:
                # TODO do logging
                response = error_handler(
                    resultCode=e.resultCode, errorMessage=e.message
                )
                self.queue(msg.id, response)
            except Exception as e:
                response = error_handler(
                    resultCode=LDAPProtocolError.resultCode, errorMessage=str(e)
                )
                self.queue(msg.id, response)


class LdapServer(BaseLdapServer):
    """An LDAP server"""

    boundUser: Optional[LdapEntry] = None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(
        self,
        request: pureldap.LDAPBindRequest,
        controls: Optional[pureldap.LDAPControls],
        reply: ReplyCallback,
    ) -> None:
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError(
                "Version %u not supported" % request.version
            )

        self.checkControls(controls)

        if request.dn == b"":
            # anonymous bind
            self.boundUser = None
            reply(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode))
            return

        dn = distinguishedname.DistinguishedName(request.dn)

        try:
            entry = await self.root.lookup(dn)
        except ldaperrors.LDAPNoSuchObject:
            raise ldaperrors.LDAPInvalidCredentials

        entry.bind(request.auth)
        self.boundUser = entry

        msg = pureldap.LDAPBindResponse(
            resultCode=ldaperrors.Success.resultCode, matchedDN=entry.dn.getText()
        )
        reply(msg)

    def handle_LDAPUnbindRequest(
        self,
        request: pureldap.LDAPUnbindRequest,
        controls: Optional[pureldap.LDAPControls],
        reply: ReplyCallback,
    ) -> None:
        # explicitly do not check unsupported critical controls -- we
        # have no way to return an error, anyway.
        self.connection_lost(None)

    fail_LDAPCompareRequest = pureldap.LDAPCompareResponse

    def handle_LDAPCompareRequest(
        self,
        request: pureldap.LDAPCompareRequest,
        controls: Optional[pureldap.LDAPControls],
        reply: ReplyCallback,
    ) -> None:
        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        base = await self.root.lookup(dn)

        # base.search only works with Filter Objects, and not with
        # AttributeValueAssertion objects. Here we convert the AVA to an
        # equivalent Filter so we can re-use the existing search
        # functionality we require.
        search_filter = pureldap.LDAPFilter_equalityMatch(
            attributeDesc=request.ava.attributeDesc,
            assertionValue=request.ava.assertionValue,
        )
        search_results = await base.search(
            filterObject=search_filter,
            scope=pureldap.LDAP_SCOPE_baseObject,
            derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
        )
        if search_results:
            reply(pureldap.LDAPCompareResponse(ldaperrors.LDAPCompareTrue.resultCode))
        else:
            reply(pureldap.LDAPCompareResponse(ldaperrors.LDAPCompareFalse.resultCode))
        return None

    fail_LDAPSearchRequest = pureldap.LDAPSearchResultDone

    def handle_LDAPSearchRequest(
        self,
        request: pureldap.LDAPSearchRequest,
        controls: Optional[pureldap.LDAPControls],
        reply: ReplyCallback,
    ) -> None:
        self.checkControls(controls)
        base_dn = distinguishedname.DistinguishedName(request.baseObject)

        # short-circuit if the requested entry is the root entry
        # TODO: check that the root entry has attributes like supportedLDAPVersion,
        #  namingContexts, supportedExtension, subschemaName ...
        if (
            request.baseObject == b""
            and request.scope == pureldap.LDAP_SCOPE_baseObject
            and request.filter == pureldap.LDAPFilter_present("objectClass")
        ):
            # prepare the attributes of the root entry as they are expected
            attributes = await self.root.fetch()
            msg = pureldap.LDAPSearchResultEntry(
                objectName=self.root.dn.getText(), attributes=attributes
            )
            reply(msg)
            msg = pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
            return None

        base = await self.root.lookup(base_dn)
        search_results = await base.search(
            filterObject=request.filter,
            attributes=request.attributes,
            scope=request.scope,
            derefAliases=request.derefAliases,
            sizeLimit=request.sizeLimit,
            timeLimit=request.timeLimit,
            typesOnly=request.typesOnly,
        )

        for entry in search_results:
            if len(request.attributes) > 0 and b"*" not in request.attributes:
                attributes = [(k, entry[k]) for k in request.attributes if k in entry]
            else:
                attributes = list(entry.items())
            msg = pureldap.LDAPSearchResultEntry(
                objectName=entry.dn.getText(), attributes=attributes
            )
            reply(msg)

        msg = pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)
        reply(msg)
        return None

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(self, request, controls, reply):
        self.checkControls(controls)

        dn = distinguishedname.DistinguishedName(request.value)
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)

        def _gotEntry(entry):
            d = entry.delete()
            return d

        def _report(entry):
            return pureldap.LDAPDelResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    def handle_LDAPAddRequest(self, request, controls, reply):
        self.checkControls(controls)

        attributes = {}
        for name, vals in request.attributes:
            attributes.setdefault(name.value, set())
            attributes[name.value].update([x.value for x in vals])
        dn = distinguishedname.DistinguishedName(request.entry)
        rdn = dn.split()[0].getText()
        parent = dn.up()
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(parent)

        def _gotEntry(parent):
            d = parent.addChild(rdn, attributes)
            return d

        def _report(entry):
            return pureldap.LDAPAddResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    def handle_LDAPModifyDNRequest(self, request, controls, reply):
        self.checkControls(controls)
        dn = distinguishedname.DistinguishedName(request.entry)
        newrdn = distinguishedname.RelativeDistinguishedName(request.newrdn)
        deleteoldrdn = bool(request.deleteoldrdn)
        if not deleteoldrdn:
            raise ldaperrors.LDAPUnwillingToPerform(
                "Cannot handle preserving old RDN yet."
            )
        newSuperior = request.newSuperior
        if newSuperior is None:
            newSuperior = dn.up()
        else:
            newSuperior = distinguishedname.DistinguishedName(newSuperior)
        newdn = distinguishedname.DistinguishedName(
            listOfRDNs=(newrdn,) + newSuperior.split()
        )
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)

        def _gotEntry(entry):
            d = entry.move(newdn)
            return d

        def _report(entry):
            return pureldap.LDAPModifyDNResponse(resultCode=0)

        d.addCallback(_gotEntry)
        d.addCallback(_report)
        return d

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    def handle_LDAPModifyRequest(self, request, controls, reply):
        self.checkControls(controls)

        root = interfaces.IConnectedLDAPEntry(self.factory)
        mod = delta.ModifyOp.fromLDAP(request)
        d = mod.patch(root)

        def _patched(entry):
            return entry.commit()

        def _report(entry):
            return pureldap.LDAPModifyResponse(resultCode=0)

        d.addCallback(_patched)
        d.addCallback(_report)
        return d

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        self.checkControls(controls)

        for handler in [
            getattr(self, attr)
            for attr in dir(self)
            if attr.startswith("extendedRequest_")
        ]:
            if getattr(handler, "oid", None) == request.requestName:
                berdecoder = getattr(handler, "berdecoder", None)

                if berdecoder is None:
                    values = [request.requestValue]
                else:
                    values = pureber.berDecodeMultiple(request.requestValue, berdecoder)

                d = defer.maybeDeferred(handler, *values, **{"reply": reply})

                def eb(fail, oid):
                    fail.trap(ldaperrors.LDAPException)
                    return pureldap.LDAPExtendedResponse(
                        resultCode=fail.value.resultCode,
                        errorMessage=fail.value.message,
                        responseName=oid,
                    )

                d.addErrback(eb, request.requestName)
                return d

        raise ldaperrors.LDAPProtocolError(
            b"Unknown extended request: %s" % request.requestName
        )

    def extendedRequest_LDAPPasswordModifyRequest(self, data, reply):
        if not isinstance(data, pureber.BERSequence):
            raise ldaperrors.LDAPProtocolError(
                "Extended request PasswordModify expected a BERSequence."
            )

        userIdentity = None
        oldPasswd = None
        newPasswd = None

        for value in data:
            if isinstance(value, pureldap.LDAPPasswordModifyRequest_userIdentity):
                if userIdentity is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request "
                        "PasswordModify received userIdentity twice."
                    )
                userIdentity = value.value
            elif isinstance(value, pureldap.LDAPPasswordModifyRequest_oldPasswd):
                if oldPasswd is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request PasswordModify " "received oldPasswd twice."
                    )
                oldPasswd = value.value
            elif isinstance(value, pureldap.LDAPPasswordModifyRequest_newPasswd):
                if newPasswd is not None:
                    raise ldaperrors.LDAPProtocolError(
                        "Extended request PasswordModify " "received newPasswd twice."
                    )
                newPasswd = value.value
            else:
                raise ldaperrors.LDAPProtocolError(
                    "Extended request PasswordModify " "received unexpected item."
                )

        if self.boundUser is None:
            raise ldaperrors.LDAPStrongAuthRequired()

        if userIdentity is not None and userIdentity != self.boundUser.dn:
            log.msg(
                "User {actor} tried to change password of {target}".format(
                    actor=self.boundUser.dn.getText(),
                    target=userIdentity,
                )
            )
            raise ldaperrors.LDAPInsufficientAccessRights()
        if oldPasswd is not None or newPasswd is None:
            raise ldaperrors.LDAPOperationsError("Password does not support this case.")
        self.boundUser.setPassword(newPasswd)
        d = self.boundUser.commit()

        def cb_(result):
            if result:
                return pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    responseName=self.extendedRequest_LDAPPasswordModifyRequest.oid,
                )
            else:
                raise ldaperrors.LDAPOperationsError("Internal error.")

        d.addCallback(cb_)
        return d

    extendedRequest_LDAPPasswordModifyRequest.oid = (
        pureldap.LDAPPasswordModifyRequest.oid
    )
    extendedRequest_LDAPPasswordModifyRequest.berdecoder = pureber.BERDecoderContext(
        inherit=pureldap.LDAPBERDecoderContext_LDAPPasswordModifyRequest(
            inherit=pureber.BERDecoderContext()
        )
    )


if __name__ == "__main__":
    """
    Demonstration LDAP server; reads LDIF from stdin and
    serves that over LDAP on port 10389.
    """
    from twisted.internet import reactor
    import sys

    log.startLogging(sys.stderr)

    from twisted.python import components
    from ldaptor import inmemory

    class LDAPServerFactory(protocol.ServerFactory):
        def __init__(self, root):
            self.root = root

    components.registerAdapter(
        lambda x: x.root, LDAPServerFactory, interfaces.IConnectedLDAPEntry
    )

    def start(db):
        factory = LDAPServerFactory(db)
        factory.protocol = LDAPServer
        reactor.listenTCP(10389, factory)

    d = inmemory.fromLDIFFile(sys.stdin)
    d.addCallback(start)
    d.addErrback(log.err)
    reactor.run()
