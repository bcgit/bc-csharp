using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Builder for <see cref="CertificateRequestMessage"/> objects.</summary>
    /// <remarks>
    /// Set the fields of the certificate template, add any controls and choose one proof of possession, then call
    /// <see cref="Build"/>.
    /// </remarks>
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

        /// <summary>Create a builder.</summary>
        /// <param name="certReqId">The identifier for the certificate request.</param>
        public CertificateRequestMessageBuilder(BigInteger certReqId)
        {
            m_certReqID = certReqId;
        }

        /// <summary>Set the registration information (regInfo) of the request.</summary>
        /// <param name="regInfo">The registration information.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetRegInfo(AttributeTypeAndValue[] regInfo)
        {
            m_regInfo = regInfo;
            return this;
        }

        /// <summary>Set the public key of the certificate template.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetPublicKey(AsymmetricKeyParameter publicKey) =>
            SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

        /// <summary>Set the public key of the certificate template.</summary>
        /// <param name="publicKeyInfo">The public key info.</param>
        /// <returns>This builder.</returns>
        [Obsolete("Use 'SetSubjectPublicKeyInfo' instead")]
        public CertificateRequestMessageBuilder SetPublicKey(SubjectPublicKeyInfo publicKeyInfo) =>
            SetSubjectPublicKeyInfo(spki: publicKeyInfo);

        /// <summary>Set the public key info of the certificate template; null is ignored.</summary>
        /// <param name="spki">The public key info.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetSubjectPublicKeyInfo(SubjectPublicKeyInfo spki)
        {
            if (spki != null)
            {
                m_templateBuilder.SetSubjectPublicKeyInfo(spki);
            }

            return this;
        }

        /// <summary>Set the issuer of the certificate template; null is ignored.</summary>
        /// <param name="issuer">The issuer name.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetIssuer(X509Name issuer)
        {
            if (issuer != null)
            {
                m_templateBuilder.SetIssuer(issuer);
            }

            return this;
        }

        /// <summary>Set the subject of the certificate template; null is ignored.</summary>
        /// <param name="subject">The subject name.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetSubject(X509Name subject)
        {
            if (subject != null)
            {
                m_templateBuilder.SetSubject(subject);
            }

            return this;
        }

        /// <summary>Set the serial number of the certificate template; null is ignored.</summary>
        /// <param name="serialNumber">The serial number.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(new DerInteger(serialNumber));
            }

            return this;
        }

        /// <summary>Set the serial number of the certificate template; null is ignored.</summary>
        /// <param name="serialNumber">The serial number.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetSerialNumber(DerInteger serialNumber)
        {
            if (serialNumber != null)
            {
                m_templateBuilder.SetSerialNumber(serialNumber);
            }

            return this;
        }

        /// <summary>Set the validity of the certificate template.</summary>
        /// <param name="validity">The validity.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetValidity(OptionalValidity validity)
        {
            m_templateBuilder.SetValidity(validity);
            return this;
        }

        /// <summary>Set the validity of the certificate template.</summary>
        /// <param name="notBefore">The start of the validity, or null.</param>
        /// <param name="notAfter">The end of the validity, or null.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetValidity(DateTime? notBefore, DateTime? notAfter)
        {
            m_templateBuilder.SetValidity(notBefore, notAfter);
            return this;
        }

        /// <summary>Add an extension to the certificate template.</summary>
        /// <param name="oid">The extension's object identifier.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="value">The extension value.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder AddExtension(DerObjectIdentifier oid, bool critical,
            Asn1Encodable value)
        {
            m_extGenerator.AddExtension(oid, critical, value);
            return this;
        }

        /// <summary>Add an extension to the certificate template.</summary>
        /// <param name="oid">The extension's object identifier.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="value">The extension value, as the contents of the extension's octet string.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder AddExtension(DerObjectIdentifier oid, bool critical,
            byte[] value)
        {
            m_extGenerator.AddExtension(oid, critical, value);
            return this;
        }

        /// <summary>Add a control to the request.</summary>
        /// <param name="control">The control.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder AddControl(IControl control)
        {
            m_controls.Add(control);
            return this;
        }

        /// <summary>Use a signature made with the private key as the proof of possession.</summary>
        /// <param name="popoSignatureFactory">The factory for the signature calculator.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="InvalidOperationException">A proof of possession has already been set.</exception>
        public CertificateRequestMessageBuilder SetProofOfPossessionSignKeySigner(
            ISignatureFactory popoSignatureFactory)
        {
            if (m_popoPrivKey != null || m_popRaVerified != null || m_agreeMac != null)
                throw new InvalidOperationException("only one proof of possession is allowed.");

            m_popSigner = popoSignatureFactory;
            return this;
        }

        /// <summary>Use a subsequent message with key encipherment as the proof of possession.</summary>
        /// <param name="msg">The subsequent message option.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="InvalidOperationException">A proof of possession has already been set.</exception>
        public CertificateRequestMessageBuilder SetProofOfPossessionSubsequentMessage(SubsequentMessage msg)
        {
            if (m_popoPrivKey != null || m_popRaVerified != null || m_agreeMac != null)
                throw new InvalidOperationException("only one proof of possession is allowed.");

            m_popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
            m_popoPrivKey = new PopoPrivKey(msg);
            return this;
        }

        /// <summary>Use a subsequent message as the proof of possession.</summary>
        /// <param name="type">The proof-of-possession type: key encipherment or key agreement.</param>
        /// <param name="msg">The subsequent message option.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="InvalidOperationException">A proof of possession has already been set.</exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="type"/> is neither key encipherment nor key agreement.
        /// </exception>
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

        /// <summary>Use a MAC from key agreement as the proof of possession.</summary>
        /// <param name="macValue">The MAC value.</param>
        /// <returns>This builder.</returns>
        /// <exception cref="InvalidOperationException">A proof of possession has already been set.</exception>
        public CertificateRequestMessageBuilder SetProofOfPossessionAgreeMac(PKMacValue macValue)
        {
            if (m_popSigner != null || m_popRaVerified != null || m_popoPrivKey != null)
                throw new InvalidOperationException("only one proof of possession allowed");

            m_agreeMac = macValue;
            return this;
        }

        /// <summary>
        /// Indicate that the registration authority has already verified possession of the private key.
        /// </summary>
        /// <returns>This builder.</returns>
        /// <exception cref="InvalidOperationException">Another proof of possession has already been set.</exception>
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

        /// <summary>
        /// Set the PKMAC builder and password used to authenticate a signing key proof of possession.
        /// </summary>
        /// <param name="pkmacFactory">The PKMAC builder.</param>
        /// <param name="password">The password for the MAC.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetAuthInfoPKMacBuilder(PKMacBuilder pkmacFactory, char[] password)
        {
            m_pkMacBuilder = pkmacFactory;
            m_password = password;
            return this;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Set the PKMAC builder and password used to authenticate a signing key proof of possession.
        /// </summary>
        /// <param name="pkmacFactory">The PKMAC builder.</param>
        /// <param name="password">The password for the MAC.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetAuthInfoPKMacBuilder(PKMacBuilder pkmacFactory,
            ReadOnlySpan<char> password)
        {
            m_pkMacBuilder = pkmacFactory;
            m_password = password.ToArray();
            return this;
        }
#endif

        /// <summary>Set the sender name used to authenticate a signing key proof of possession.</summary>
        /// <param name="sender">The sender name.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetAuthInfoSender(X509Name sender) =>
            SetAuthInfoSender(new GeneralName(sender));

        /// <summary>Set the sender name used to authenticate a signing key proof of possession.</summary>
        /// <param name="sender">The sender name.</param>
        /// <returns>This builder.</returns>
        public CertificateRequestMessageBuilder SetAuthInfoSender(GeneralName sender)
        {
            m_sender = sender;
            return this;
        }

        /// <summary>Build the certificate request message.</summary>
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

                // RFC 4211 sec. 4.1: the signature can only be verified against the public key in the
                // template, which poposkInput (when present) must also carry.
                SubjectPublicKeyInfo pubKeyInfo = template.PublicKey
                    ?? throw new CrmfException(
                        "signing key proof of possession requires a public key in the certificate template");

                ProofOfPossessionSigningKeyBuilder builder;
                if (template.Subject == null)
                {
                    builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

                    if (m_sender != null)
                    {
                        builder.SetSender(m_sender);
                    }
                    else if (m_pkMacBuilder != null)
                    {
                        builder.SetPublicKeyMac(m_pkMacBuilder, m_password);
                    }
                    else
                    {
                        throw new CrmfException(
                            "signing key proof of possession without a subject in the certificate template requires an authInfo sender or PKMAC");
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
