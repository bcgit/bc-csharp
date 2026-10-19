using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base class for a TLS client or server.</summary>
    public abstract class AbstractTlsPeer
        : TlsPeer
    {
        private readonly TlsCrypto m_crypto;

        private volatile TlsCloseable m_closeHandle;

        /// <summary>Create a new <see cref="AbstractTlsPeer"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        protected AbstractTlsPeer(TlsCrypto crypto)
        {
            m_crypto = crypto;
        }

        /// <summary>Get the <see cref="ProtocolVersion"/> values that are supported by this peer.</summary>
        /// <remarks>
        /// WARNING: Mixing DTLS and TLS versions in the returned array is currently NOT supported. Use a separate
        /// (sub-)class for each case.
        /// </remarks>
        /// <returns>an array of supported <see cref="ProtocolVersion"/> values.</returns>
        protected virtual ProtocolVersion[] GetSupportedVersions() =>
            ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);

        /// <summary>Return the supported cipher suites.</summary>
        protected abstract int[] GetSupportedCipherSuites();

        /// <exception cref="IOException"/>
        public virtual void Cancel() => m_closeHandle?.Close();

        public virtual TlsCrypto Crypto => m_crypto;

        /// <inheritdoc/>
        public virtual void NotifyCloseHandle(TlsCloseable closeHandle)
        {
            m_closeHandle = closeHandle;
        }

        /// <inheritdoc/>
        public abstract ProtocolVersion[] GetProtocolVersions();

        /// <inheritdoc/>
        public abstract int[] GetCipherSuites();

        /// <exception cref="IOException"/>
        public virtual void NotifyHandshakeBeginning()
        {
        }

        /// <inheritdoc/>
        public virtual int GetHandshakeTimeoutMillis() => 0;

        /// <inheritdoc/>
        public virtual int GetHandshakeResendTimeMillis() => 1000;

        /// <inheritdoc/>
        public virtual bool AllowLegacyResumption() => false;

        /// <inheritdoc/>
        public virtual int GetMaxCertificateChainLength() => 10;

        /// <inheritdoc/>
        public virtual int GetMaxHandshakeMessageSize() => 32768;

        /// <inheritdoc/>
        public virtual short[] GetPskKeyExchangeModes() => new short[]{ PskKeyExchangeMode.psk_dhe_ke };

        /// <inheritdoc/>
        public virtual bool RequiresCloseNotify() => true;

        /// <inheritdoc/>
        public virtual bool RequiresExtendedMasterSecret() => false;

        public virtual bool ShouldCheckSigAlgOfPeerCerts() => true;

        /// <inheritdoc/>
        public virtual bool ShouldUseExtendedMasterSecret() => true;

        /// <inheritdoc/>
        public virtual bool ShouldUseExtendedPadding() => false;

        /*
         * draft-mathewson-no-gmtunixtime-00 2. For the reasons we discuss above, we recommend that TLS implementors
         * MUST by default set the entire value the ClientHello.Random and ServerHello.Random fields, including
         * gmt_unix_time, to a cryptographically random sequence.
         */
        public virtual bool ShouldUseGmtUnixTime() => false;

        /// <exception cref="IOException"/>
        public virtual void NotifySecureRenegotiation(bool secureRenegotiation)
        {
            if (!secureRenegotiation)
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        /// <exception cref="IOException"/>
        public virtual TlsKeyExchangeFactory GetKeyExchangeFactory() => new DefaultTlsKeyExchangeFactory();

        /// <inheritdoc/>
        public virtual void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
        }

        /// <inheritdoc/>
        public virtual void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
        }

        /// <inheritdoc/>
        public virtual void NotifyConnectionClosed()
        {
        }

        /// <exception cref="IOException"/>
        public virtual void NotifyHandshakeComplete()
        {
        }

        /// <inheritdoc/>
        public virtual TlsHeartbeat GetHeartbeat() => null;

        /// <inheritdoc/>
        public virtual short GetHeartbeatPolicy() => HeartbeatMode.peer_not_allowed_to_send;

        /// <inheritdoc/>
        [Obsolete("Will be removed")]
        public virtual bool IgnoreCorruptDtlsRecords => false;
    }
}
