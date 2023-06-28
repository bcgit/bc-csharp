﻿using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTlsServer
        : PskTlsServer
    {
        internal MockPskTlsServer()
            : base(new BcTlsCrypto(), new MyIdentityManager())
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
            output.WriteLine("TLS-PSK server raised alert: " + AlertLevel.GetText(alertLevel)
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
            output.WriteLine("TLS-PSK server received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            Console.WriteLine("TLS-PSK server negotiated " + serverVersion);

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

            byte[] pskIdentity = m_context.SecurityParameters.PskIdentity;
            if (pskIdentity != null)
            {
                string name = Strings.FromUtf8ByteArray(pskIdentity);
                Console.WriteLine("TLS-PSK server completed handshake for PSK identity: " + name);
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

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            return TlsTestUtilities.LoadEncryptionCredentials(m_context,
                new string[] { "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" }, "x509-server-key-rsa-enc.pem");
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv12.Only();
        }

        internal class MyIdentityManager
            : TlsPskIdentityManager
        {
            public byte[] GetHint()
            {
                return Strings.ToUtf8ByteArray("hint");
            }

            public byte[] GetPsk(byte[] identity)
            {
                if (identity != null)
                {
                    string name = Strings.FromUtf8ByteArray(identity);
                    if (name.Equals("client"))
                    {
                        return Strings.ToUtf8ByteArray("TLS_TEST_PSK");
                    }
                }
                return null;
            }
        }
    }
}
