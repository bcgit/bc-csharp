using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockSrpTlsServer
        : SrpTlsServer
    {
        private const string PeerName = "TLS-SRP server";

        internal static readonly Srp6Group TEST_GROUP = Tls.Crypto.Srp6StandardGroups.rfc5054_1024;
        internal static readonly byte[] TEST_IDENTITY = Strings.ToUtf8ByteArray("client");
        internal static readonly byte[] TEST_PASSWORD = Strings.ToUtf8ByteArray("password");
        internal static readonly TlsSrpIdentity TEST_SRP_IDENTITY = new BasicTlsSrpIdentity(TEST_IDENTITY,
            TEST_PASSWORD);
        internal static readonly byte[] TEST_SALT = Strings.ToUtf8ByteArray("salt");
        internal static readonly byte[] TEST_SEED_KEY = Strings.ToUtf8ByteArray("seed_key");

        internal MockSrpTlsServer()
            : base(new BcTlsCrypto(), new MyIdentityManager(new BcTlsCrypto()))
        {
        }

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TlsTestUtilities.LogAlert(PeerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(PeerName, false, alertLevel, alertDescription, null, null);

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            TlsTestUtilities.Log(PeerName + " negotiated version " + serverVersion);

            return serverVersion;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(PeerName, m_context);

            byte[] srpIdentity = m_context.SecurityParameters.SrpIdentity;
            if (srpIdentity != null)
            {
                TlsTestUtilities.Log(PeerName + " completed handshake for SRP identity: "
                    + Strings.FromUtf8ByteArray(srpIdentity));
            }
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            TlsTestUtilities.CheckClientRandom(m_context);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected override TlsCredentialedSigner GetDsaSignerCredentials()
        {
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, m_context.SecurityParameters.ClientSigAlgs,
                SignatureAlgorithm.dsa);
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, m_context.SecurityParameters.ClientSigAlgs,
                SignatureAlgorithm.rsa);
        }

        internal class MyIdentityManager
            : TlsSrpIdentityManager
        {
            protected SimulatedTlsSrpIdentityManager m_unknownIdentityManager;

            internal MyIdentityManager(TlsCrypto crypto)
            {
                m_unknownIdentityManager = SimulatedTlsSrpIdentityManager.GetRfc5054Default(crypto, TEST_GROUP,
                    TEST_SEED_KEY);
            }

            public TlsSrpLoginParameters GetLoginParameters(byte[] identity)
            {
                if (Arrays.FixedTimeEquals(TEST_IDENTITY, identity))
                {
                    Srp6VerifierGenerator verifierGenerator = new Srp6VerifierGenerator();
                    verifierGenerator.Init(TEST_GROUP.N, TEST_GROUP.G, new Sha1Digest());

                    BigInteger verifier = verifierGenerator.GenerateVerifier(TEST_SALT, identity, TEST_PASSWORD);

                    TlsSrpConfig srpConfig = new TlsSrpConfig();
                    srpConfig.SetExplicitNG(new BigInteger[]{ TEST_GROUP.N, TEST_GROUP.G });

                    return new TlsSrpLoginParameters(identity, srpConfig, verifier, TEST_SALT);
                }

                return m_unknownIdentityManager.GetLoginParameters(identity);
            }
        }
    }
}
