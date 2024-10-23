using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crmf
{
    public class CertificateRequestMessageBuilder
    {
        private readonly List<IControl> m_controls = new List<IControl>();
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();
        private readonly CertTemplateBuilder m_templateBuilder = new CertTemplateBuilder();

        private readonly BigInteger m_certReqID;

        private ISignatureFactory m_popSigner = null;
        private PKMacBuilder m_pkMacBuilder = null;
        private char[] m_password = null;
        private GeneralName m_sender = null;
        private int m_popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
        private PopoPrivKey m_popoPrivKey = null;
        private Asn1Null m_popRaVerified = null;
        private PKMacValue m_agreeMac = null;
        private AttributeTypeAndValue[] m_regInfo = null;

        public CertificateRequestMessageBuilder(BigInteger certReqId)
        {
            m_certReqID = certReqId;
        }

        public CertificateRequestMessageBuilder SetRegInfo(AttributeTypeAndValue[] regInfo)
        {
            m_regInfo = regInfo;
            return this;
        }

        public CertificateRequestMessageBuilder SetPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        {
            if (publicKeyInfo != null)
            {
                m_templateBuilder.SetPublicKey(publicKeyInfo);
            }

            return this;
        }

        public CertificateRequestMessageBuilder SetIssuer(X509Name issuer)
        {
            if (issuer != null)
            {
                m_templateBuilder.SetIssuer(issuer);
            }

            return this;
        }

        public CertificateRequestMessageBuilder SetSubject(X509Name subject)
        {
            if (subject != null)
            {
                m_templateBuilder.SetSubject(subject);
            }

            return this;
        }

        public CertificateRequestMessageBuilder SetSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
            }

            return this;
        }

        public CertificateRequestMessageBuilder SetSerialNumber(DerInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(serialNumber);
            }

            return this;
        }

        public CertificateRequestMessageBuilder SetValidity(OptionalValidity validity)
        {
            m_templateBuilder.SetValidity(validity);
            return this;
        }

        public CertificateRequestMessageBuilder SetValidity(DateTime? notBefore, DateTime? notAfter)
        {
            m_templateBuilder.SetValidity(notBefore, notAfter);
            return this;
        }

        public CertificateRequestMessageBuilder AddExtension(DerObjectIdentifier oid, bool critical,
            Asn1Encodable value)
        {
            m_extGenerator.AddExtension(oid, critical, value);
            return this;
        }

        public CertificateRequestMessageBuilder AddExtension(DerObjectIdentifier oid, bool critical,
            byte[] value)
        {
            m_extGenerator.AddExtension(oid, critical, value);
            return this;
        }

        public CertificateRequestMessageBuilder AddControl(IControl control)
        {
            m_controls.Add(control);
            return this;
        }

        public CertificateRequestMessageBuilder SetProofOfPossessionSignKeySigner(
            ISignatureFactory popoSignatureFactory)
        {
            if (m_popoPrivKey != null || m_popRaVerified != null || m_agreeMac != null)
                throw new InvalidOperationException("only one proof of possession is allowed.");

            m_popSigner = popoSignatureFactory;
            return this;
        }

        public CertificateRequestMessageBuilder SetProofOfPossessionSubsequentMessage(SubsequentMessage msg)
        {
            if (m_popoPrivKey != null || m_popRaVerified != null || m_agreeMac != null)
                throw new InvalidOperationException("only one proof of possession is allowed.");

            m_popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
            m_popoPrivKey = new PopoPrivKey(msg);
            return this;
        }

        public CertificateRequestMessageBuilder SetProofOfPossessionSubsequentMessage(int type, SubsequentMessage msg)
        {
            if (m_popoPrivKey != null || m_popRaVerified != null || m_agreeMac != null)
                throw new InvalidOperationException("only one proof of possession is allowed.");
            if (type != ProofOfPossession.TYPE_KEY_ENCIPHERMENT && type != ProofOfPossession.TYPE_KEY_AGREEMENT)
                throw new ArgumentException("type must be ProofOfPossession.TYPE_KEY_ENCIPHERMENT or ProofOfPossession.TYPE_KEY_AGREEMENT");

            m_popoType = type;
            m_popoPrivKey = new PopoPrivKey(msg);
            return this;
        }

        public CertificateRequestMessageBuilder SetProofOfPossessionAgreeMac(PKMacValue macValue)
        {
            if (m_popSigner != null || m_popRaVerified != null || m_popoPrivKey != null)
                throw new InvalidOperationException("only one proof of possession allowed");

            m_agreeMac = macValue;
            return this;
        }

        public CertificateRequestMessageBuilder SetProofOfPossessionRaVerified()
        {
            if (m_popSigner != null || m_popoPrivKey != null)
                throw new InvalidOperationException("only one proof of possession allowed");

            m_popRaVerified = DerNull.Instance;
            return this;
        }

        [Obsolete("Use 'SetAuthInfoPKMacBuilder' instead")]
        public CertificateRequestMessageBuilder SetAuthInfoPKMAC(PKMacBuilder pkmacFactory, char[] password)
        {
            return SetAuthInfoPKMacBuilder(pkmacFactory, password);
        }

        public CertificateRequestMessageBuilder SetAuthInfoPKMacBuilder(PKMacBuilder pkmacFactory, char[] password)
        {
            m_pkMacBuilder = pkmacFactory;
            m_password = password;
            return this;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public CertificateRequestMessageBuilder SetAuthInfoPKMacBuilder(PKMacBuilder pkmacFactory,
            ReadOnlySpan<char> password)
        {
            m_pkMacBuilder = pkmacFactory;
            m_password = password.ToArray();
            return this;
        }
#endif

        public CertificateRequestMessageBuilder SetAuthInfoSender(X509Name sender) =>
            SetAuthInfoSender(new GeneralName(sender));

        public CertificateRequestMessageBuilder SetAuthInfoSender(GeneralName sender)
        {
            m_sender = sender;
            return this;
        }

        public CertificateRequestMessage Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(new DerInteger(m_certReqID));

            if (!m_extGenerator.IsEmpty)
            {
                m_templateBuilder.SetExtensions(m_extGenerator.Generate());
            }

            v.Add(m_templateBuilder.Build());

            if (m_controls.Count > 0)
            {
                Asn1EncodableVector controlV = new Asn1EncodableVector(m_controls.Count);

                foreach (var control in m_controls)
                {
                    controlV.Add(new AttributeTypeAndValue(control.Type, control.Value));
                }

                v.Add(new DerSequence(controlV));
            }

            CertRequest request = CertRequest.GetInstance(new DerSequence(v));

            ProofOfPossession proofOfPossession;
            if (m_popSigner != null)
            {
                CertTemplate template = request.CertTemplate;

                ProofOfPossessionSigningKeyBuilder builder;
                if (template.Subject == null || template.PublicKey == null)
                {
                    SubjectPublicKeyInfo pubKeyInfo = request.CertTemplate.PublicKey;

                    builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

                    if (m_sender != null)
                    {
                        builder.SetSender(m_sender);
                    }
                    else
                    {
                        builder.SetPublicKeyMac(m_pkMacBuilder, m_password);
                    }
                }
                else
                {
                    builder = new ProofOfPossessionSigningKeyBuilder(request);
                }

                proofOfPossession = new ProofOfPossession(builder.Build(m_popSigner));
            }
            else if (m_popoPrivKey != null)
            {
                proofOfPossession = new ProofOfPossession(m_popoType, m_popoPrivKey);
            }
            else if (m_agreeMac != null)
            {
                proofOfPossession = new ProofOfPossession(ProofOfPossession.TYPE_KEY_AGREEMENT, new PopoPrivKey(m_agreeMac));
            }
            else if (m_popRaVerified != null)
            {
                proofOfPossession = new ProofOfPossession();
            }
            else
            {
                proofOfPossession = new ProofOfPossession();
            }

            CertReqMsg certReqMsg = new CertReqMsg(request, proofOfPossession, m_regInfo);

            return new CertificateRequestMessage(certReqMsg);
        }
    }
}
