using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockSrpTlsServer
        : SrpTlsServer
    {
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

        protected override IList<ProtocolName> GetProtocolNames()
        {
            var protocolNames = new List<ProtocolName>();
            protocolNames.Add(ProtocolName.Http_2_Tls);
            protocolNames.Add(ProtocolName.Http_1_1);
            return protocolNames;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS-SRP server raised alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS-SRP server received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            Console.WriteLine("TLS-SRP server negotiated " + serverVersion);

            return serverVersion;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Server ALPN: " + protocolName.GetUtf8Decoding());
            }

            byte[] tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            Console.WriteLine("Server 'tls-server-end-point': " + ToHexString(tlsServerEndPoint));

            byte[] tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);
            Console.WriteLine("Server 'tls-unique': " + ToHexString(tlsUnique));

            byte[] srpIdentity = m_context.SecurityParameters.SrpIdentity;
            if (srpIdentity != null)
            {
                string name = Strings.FromUtf8ByteArray(srpIdentity);
                Console.WriteLine("TLS-SRP server completed handshake for SRP identity: " + name);
            }
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected override TlsCredentialedSigner GetDsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, clientSigAlgs, SignatureAlgorithm.dsa);
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            var clientSigAlgs = m_context.SecurityParameters.ClientSigAlgs;
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, clientSigAlgs, SignatureAlgorithm.rsa);
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
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
