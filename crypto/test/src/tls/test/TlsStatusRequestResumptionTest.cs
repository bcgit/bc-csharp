using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// What a server puts in an abbreviated handshake's ServerHello, where "status_request" is concerned.
    /// </summary>
    /// <remarks>
    /// A session stores the extensions the server sent when it was established, and a resumed handshake replays them -
    /// but the status_request echo announces a CertificateStatus message, and an abbreviated handshake sends neither a
    /// Certificate nor a CertificateStatus. Replaying it hands the client an extension answering nothing, and one the
    /// resuming ClientHello need not even have offered: RFC 5246 sec. 7.4.1.4 has a client abort with
    /// unsupported_extension over an extension it did not request.
    /// <para>
    /// Observed through <see cref="TlsServer.GetServerExtensionsForConnection(IDictionary{int, byte[]})"/>, which the
    /// protocol hands the very extensions it is about to send.
    /// </para>
    /// </remarks>
    [TestFixture]
    public class TlsStatusRequestResumptionTest
    {
        [Test]
        public void ResumedHandshakeDropsTheStatusRequestEcho()
        {
            StatusRequestTlsServer server = new StatusRequestTlsServer();

            // a full handshake, with the client asking - so the echo goes into the session
            TlsSession session = RunHandshake(server, null, true);

            Assert.NotNull(session, "no resumable session was established");
            Assert.False(server.WasResumed(0), "the first handshake should not have resumed");
            Assert.True(server.SentExtension(0, ExtensionType.status_request),
                "the full handshake should have echoed status_request");

            /*
             * The resuming client does not ask this time, which is what makes the replay an unsolicited extension
             * rather than merely a useless one.
             */
            RunHandshake(server, session, false);

            Assert.True(server.WasResumed(1), "the second handshake did not resume");
            Assert.False(server.SentExtension(1, ExtensionType.status_request),
                "a resumed ServerHello must not echo status_request");
            Assert.False(server.SentExtension(1, ExtensionType.status_request_v2),
                "a resumed ServerHello must not echo status_request_v2");
        }

        private TlsSession RunHandshake(StatusRequestTlsServer server, TlsSession sessionToResume,
            bool offerStatusRequest)
        {
            StatusRequestTlsClient client = new StatusRequestTlsClient(sessionToResume, offerStatusRequest);

            TlsLoopback.Run(client, server).ThrowIfFailed();

            return client.m_session;
        }

        /// <summary>
        /// Pinned to TLS 1.2: the abbreviated handshake this is about is a TLS 1.2 mechanism, where TLS 1.3 resumes
        /// with a pre-shared key instead and carries no such echo.
        /// </summary>
        private class StatusRequestTlsClient
            : MockTlsClient
        {
            private readonly bool offerStatusRequest;

            internal StatusRequestTlsClient(TlsSession session, bool offerStatusRequest)
                : base(session)
            {
                this.offerStatusRequest = offerStatusRequest;
            }

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            protected override CertificateStatusRequest GetCertificateStatusRequest() =>
                offerStatusRequest ? base.GetCertificateStatusRequest() : null;
        }

        /// <summary>
        /// A server that answers status requests - which is all it takes for the echo to be sent and stored - and that
        /// keeps one session, so a second handshake has something to resume. It records the extensions it sends per
        /// handshake for the test to read back.
        /// </summary>
        private class StatusRequestTlsServer
            : MockTlsServer
        {
            private readonly List<HashSet<int>> SentExtensions = new List<HashSet<int>>();
            private readonly List<bool> Resumed = new List<bool>();

            private TlsSession m_session = null;

            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            protected override bool AllowCertificateStatus() => true;

            // AbstractTlsServer issues none by default, and without one there is nothing to resume
            public override byte[] GetNewSessionID() => SecureRandom.GetNextBytes(m_context.Crypto.SecureRandom, 32);

            /**
            * Kept from here rather than from notifySession, which the protocol calls while the session
            * still has no parameters attached and so is not yet resumable.
            */
            public override void NotifyHandshakeComplete()
            {
                base.NotifyHandshakeComplete();

                TlsSession newSession = m_context.Session;
                if (null != newSession && newSession.IsResumable)
                {
                    m_session = newSession;
                }
            }

            public override TlsSession GetSessionToResume(byte[] sessionID) =>
                null != m_session && Arrays.AreEqual(sessionID, m_session.SessionID) ? m_session : null;

            public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
            {
                base.GetServerExtensionsForConnection(serverExtensions);

                HashSet<int> keys = new HashSet<int>(serverExtensions.Keys);

                lock (this)
                {
                    SentExtensions.Add(keys);
                    Resumed.Add(m_context.SecurityParameters.IsResumedSession);
                }
            }

            internal bool SentExtension(int handshake, int extensionType)
            {
                lock (this) return SentExtensions[handshake].Contains(extensionType);
            }

            internal bool WasResumed(int handshake)
            {
                lock (this) return Resumed[handshake];
            }
        }
    }
}
