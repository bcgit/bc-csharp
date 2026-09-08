using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base interface for a (D)TLS endpoint.</summary>
    public interface TlsPeer
    {
        TlsCrypto Crypto { get; }

        void NotifyCloseHandle(TlsCloseable closehandle);

        /// <exception cref="IOException"/>
        void Cancel();

        ProtocolVersion[] GetProtocolVersions();

        int[] GetCipherSuites();

        /// <summary>Notifies the peer that a new handshake is about to begin.</summary>
        /// <exception cref="IOException"/>
        void NotifyHandshakeBeginning();

        /// <summary>Specify the timeout, in milliseconds, to use for the complete handshake process.</summary>
        /// <remarks>
        /// NOTE: Respected by the DTLS protocols, and by the blocking <see cref="TlsClientProtocol"/> /
        /// <see cref="TlsServerProtocol"/> stream API. The stream API enforces it at record boundaries: a
        /// caller-supplied input <see cref="Stream"/> has no timed-read primitive, so a peer that stalls part way
        /// through a record blocks in the read itself, where only the transport's own read timeout can intervene.
        /// The non-blocking API is driven by the caller's own I/O loop, which is where a deadline for it belongs.
        /// </remarks>
        /// <returns>the handshake timeout, in milliseconds.</returns>
        int GetHandshakeTimeoutMillis();

        // TODO[api]
        /*
        /// <summary>Specify the time, in milliseconds, after which a handshake packet is resent.</summary>
        /// <remarks>
        /// NOTE: Currently only respected by DTLS protocols.
        /// </remarks>
        /// <returns>the handshake resend time, in milliseconds.</returns>
        int GetHandshakeResendTimeMillis();
        */

        bool AllowLegacyResumption();

        int GetMaxCertificateChainLength();

        int GetMaxHandshakeMessageSize();

        short[] GetPskKeyExchangeModes();

        /// <remarks>
        /// This option is provided as a last resort for interoperability with TLS peers that fail to correctly send a
        /// close_notify alert at end of stream. Implementations SHOULD return true; caution is advised if returning
        /// false without a full understanding of the implications.
        /// </remarks>
        bool RequiresCloseNotify();

        /// <remarks>This implementation supports RFC 7627 and will always negotiate the extended_master_secret
        /// extension where possible. When connecting to a peer that does not offer/accept this extension, it is
        /// recommended to abort the handshake.This option is provided for interoperability with legacy peers, although
        /// some TLS features will be disabled in that case (see RFC 7627 5.4).
        /// </remarks>
        /// <returns><c>true</c> if the handshake should be aborted when the peer does not negotiate the
        /// extended_master_secret extension, or <c>false</c> to support legacy interoperability.</returns>
        bool RequiresExtendedMasterSecret();

        bool ShouldUseExtendedMasterSecret();

        /// <summary>See RFC 5246 6.2.3.2. Controls whether block cipher encryption may randomly add extra padding
        /// beyond the minimum.</summary>
        /// <remarks>
        /// Note that in configurations where this is known to be potential security risk this setting will be ignored
        /// (and extended padding disabled). Extra padding is always supported when decrypting received records.
        /// </remarks>
        /// <returns><c>true</c> if random extra padding should be added during block cipher encryption, or
        /// <c>false</c> to always use the minimum amount of required padding.</returns>
        bool ShouldUseExtendedPadding();

        /// <summary> draft-mathewson-no-gmtunixtime-00 2. "If existing users of a TLS implementation may rely on
        /// gmt_unix_time containing the current time, we recommend that implementors MAY provide the ability to set
        /// gmt_unix_time as an option only, off by default.".</summary>
        /// <remarks>
        /// NOTE: For a server that has negotiated TLS 1.3 (or later), or a client that has offered TLS 1.3 (or later),
        /// this is not called and gmt_unix_time is not used.
        /// </remarks>
        /// <returns><c>true</c> if the current time should be used in the gmt_unix_time field of Random, or
        /// <c>false</c> if gmt_unix_time should contain a cryptographically random value.</returns>
        bool ShouldUseGmtUnixTime();

        /// <summary>RFC 5746 3.4/3.6. In case this is false, peers may want to terminate the handshake instead of
        /// continuing; see Section 4.1/4.3 for discussion.</summary>
        /// <remarks>
        /// NOTE: TLS 1.3 forbids renegotiation, so this is never called when TLS 1.3 (or later) was negotiated.
        /// </remarks>
        /// <exception cref="IOException"/>
        void NotifySecureRenegotiation(bool secureRenegotiation);

        /// <exception cref="IOException"/>
        TlsKeyExchangeFactory GetKeyExchangeFactory();

        /// <summary>This method will be called when an alert is raised by the protocol.</summary>
        /// <param name="alertLevel"><see cref="AlertLevel"/></param>
        /// <param name="alertDescription"><see cref="AlertDescription"/></param>
        /// <param name="message">A human-readable message explaining what caused this alert. May be null.</param>
        /// <param name="cause">The <see cref="Exception"/> that caused this alert to be raised. May be null.</param>
        void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause);

        /// <summary>This method will be called when an alert is received from the remote peer.</summary>
        /// <param name="alertLevel"><see cref="AlertLevel"/></param>
        /// <param name="alertDescription"><see cref="AlertDescription"/></param>
        void NotifyAlertReceived(short alertLevel, short alertDescription);

        // TODO[api]
        /*
        /// <summary>Notifies the peer that the connection has been closed.</summary>
        void NotifyConnectionClosed();
        */

        /// <summary>Notifies the peer that the handshake has been successfully completed.</summary>
        /// <exception cref="IOException"/>
        void NotifyHandshakeComplete();

        /// <summary>Return a <see cref="TlsHeartbeat"/> instance that will control the generation of heartbeats
        /// locally (if permitted by the remote peer), or null to not generate heartbeats. Heartbeats are described in
        /// RFC 6520.</summary>
        /// <returns>an instance of <see cref="TlsHeartbeat"/>.</returns>
        /// <seealso cref="DefaultTlsHeartbeat"/>
        TlsHeartbeat GetHeartbeat();

        /// <summary>Return the heartbeat mode applicable to the remote peer. Heartbeats are described in RFC 6520.
        /// </summary>
        /// <remarks>
        /// See enumeration class <see cref="HeartbeatMode"/> for appropriate return values.
        /// </remarks>
        /// <returns>the <see cref="HeartbeatMode"/> value.</returns>
        short GetHeartbeatPolicy();

        // TODO[api] Remove this; the DTLS record layer now unconditionally discards invalid records
        /// <summary>Formerly indicated whether a DTLS connection should ignore corrupt records (bad_record_mac)
        /// instead of failing the connection.</summary>
        /// <remarks>This value is no longer consulted. Invalid DTLS records (bad MAC, invalid length, etc.) are
        /// always silently discarded, preserving the association, per RFC 9147 section 4.5.2 and RFC 9146
        /// section 6.</remarks>
        /// <returns>Ignored.</returns>
        [Obsolete("Will be removed")]
        bool IgnoreCorruptDtlsRecords { get; }
    }
}
