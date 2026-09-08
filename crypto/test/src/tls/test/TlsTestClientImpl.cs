using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The client end of the generated <see cref="TlsTestSuite"/> cases, driven by a
    /// <see cref="TlsTestConfig"/>.</summary>
    internal class TlsTestClientImpl
        : MockTlsClient
    {
        protected readonly TlsTestConfig m_config;

        internal TlsTestClientImpl(TlsTestConfig config)
            : base(TlsTestSuite.GetCrypto(config), null)
        {
            this.m_config = config;

            AddTestExtensions = false;
            ProtocolNames = null;
            SupportedVersions = config.clientSupportedVersions;
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var clientExtensions = base.GetClientExtensions();
            if (clientExtensions != null)
            {
                if (!m_config.clientSendSignatureAlgorithms)
                {
                    clientExtensions.Remove(ExtensionType.signature_algorithms);
                    this.m_supportedSignatureAlgorithms = null;
                }
                if (!m_config.clientSendSignatureAlgorithmsCert)
                {
                    clientExtensions.Remove(ExtensionType.signature_algorithms_cert);
                    this.m_supportedSignatureAlgorithmsCert = null;
                }
            }
            return clientExtensions;
        }

        public override IList<int> GetEarlyKeyShareGroups() =>
            m_config.clientEmptyKeyShare ? null : base.GetEarlyKeyShareGroups();

        protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms()
        {
            if (m_config.clientCHSigAlgs != null)
                return TlsUtilities.GetSupportedSignatureAlgorithms(m_context, m_config.clientCHSigAlgs);

            return base.GetSupportedSignatureAlgorithms();
        }

        public override bool IsFallback() => m_config.clientFallback;

        protected override void VerifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            TlsTestUtilities.VerifyServerCertificate(m_context, serverCertificate,
                TlsTestUtilities.TrustedServerCertResources, m_config.clientCheckSigAlgOfServerCerts);
        }

        protected override TlsCredentials SelectClientCredentials(CertificateRequest certificateRequest)
        {
            if (m_config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                throw new InvalidOperationException();
            if (m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
                return null;

            if (!TlsUtilities.IsTlsV13(m_context))
            {
                short[] certificateTypes = certificateRequest.CertificateTypes;
                if (certificateTypes == null || !Arrays.Contains(certificateTypes, ClientCertificateType.rsa_sign))
                    return null;
            }

            var supportedSigAlgs = certificateRequest.SupportedSignatureAlgorithms;
            if (supportedSigAlgs != null && m_config.clientAuthSigAlg != null)
            {
                supportedSigAlgs = TlsUtilities.VectorOfOne(m_config.clientAuthSigAlg);
            }

            // TODO[tls13] Check also supportedSigAlgsCert against the chain signature(s)

            TlsCredentialedSigner signerCredentials = TlsTestUtilities.LoadSignerCredentials(m_context,
                supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
            if (signerCredentials == null && supportedSigAlgs != null)
            {
                SignatureAndHashAlgorithm pss = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                if (TlsUtilities.ContainsSignatureAlgorithm(supportedSigAlgs, pss))
                {
                    signerCredentials = TlsTestUtilities.LoadSignerCredentials(m_context,
                        new string[]{ "x509-client-rsa.pem" }, "x509-client-key-rsa.pem", pss);
                }
            }

            if (m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
                return signerCredentials;

            return new MyTlsCredentialedSigner(this, signerCredentials);
        }

        protected virtual Certificate CorruptCertificate(Certificate cert)
        {
            CertificateEntry[] certEntryList = cert.GetCertificateEntryList();
            CertificateEntry ee = certEntryList[0];
            TlsCertificate corruptCert = CorruptCertificateSignature(ee.Certificate);
            certEntryList[0] = new CertificateEntry(corruptCert, ee.Extensions);
            return new Certificate(cert.GetCertificateRequestContext(), certEntryList);
        }

        protected virtual TlsCertificate CorruptCertificateSignature(TlsCertificate tlsCertificate)
        {
            X509CertificateStructure cert = X509CertificateStructure.GetInstance(tlsCertificate.GetEncoded());

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(cert.TbsCertificate);
            v.Add(cert.SignatureAlgorithm);
            v.Add(CorruptSignature(cert.Signature));

            cert = X509CertificateStructure.GetInstance(new DerSequence(v));

            return Crypto.CreateCertificate(cert.GetEncoded(Asn1Encodable.Der));
        }

        protected virtual DerBitString CorruptSignature(DerBitString bs)
        {
            return new DerBitString(CorruptBit(bs.GetOctets()));
        }

        protected virtual byte[] CorruptBit(byte[] bs)
        {
            bs = Arrays.Clone(bs);

            // Flip a random bit
            int bit = m_context.Crypto.SecureRandom.Next(bs.Length << 3);
            bs[bit >> 3] ^= (byte)(1 << (bit & 7));

            return bs;
        }

        internal class MyTlsCredentialedSigner
            : TlsCredentialedSigner
        {
            private readonly TlsTestClientImpl m_outer;
            private readonly TlsCredentialedSigner m_inner;

            internal MyTlsCredentialedSigner(TlsTestClientImpl outer, TlsCredentialedSigner inner)
            {
                this.m_outer = outer;
                this.m_inner = inner;
            }

            public virtual byte[] GenerateRawSignature(byte[] hash)
            {
                byte[] sig = m_inner.GenerateRawSignature(hash);

                if (m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                {
                    sig = m_outer.CorruptBit(sig);
                }

                return sig;
            }

            public virtual Certificate Certificate
            {
                get
                {
                    Certificate cert = m_inner.Certificate;

                    if (m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
                    {
                        cert = m_outer.CorruptCertificate(cert);
                    }

                    return cert;
                }
            }

            public virtual SignatureAndHashAlgorithm SignatureAndHashAlgorithm
            {
                get { return m_inner.SignatureAndHashAlgorithm; }
            }

            public virtual TlsStreamSigner GetStreamSigner()
            {
                TlsStreamSigner streamSigner = m_inner.GetStreamSigner();

                if (streamSigner != null && m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                    return new CorruptingStreamSigner(m_outer, streamSigner);

                return streamSigner;
            }
        }

        internal class CorruptingStreamSigner
            : TlsStreamSigner
        {
            private readonly TlsTestClientImpl m_outer;
            private readonly TlsStreamSigner m_inner;

            internal CorruptingStreamSigner(TlsTestClientImpl outer, TlsStreamSigner inner)
            {
                this.m_outer = outer;
                this.m_inner = inner;
            }

            public Stream Stream
            {
                get { return m_inner.Stream; }
            }

            public byte[] GetSignature()
            {
                return m_outer.CorruptBit(m_inner.GetSignature());
            }
        }
    }
}
