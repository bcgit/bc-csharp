using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>
    /// Wrapper for a PKIMessage with protection attached to it.
    /// </summary>
    public class ProtectedPkiMessage
    {
        private readonly PkiMessage m_pkiMessage;

        /// <summary>
        /// Wrap a general message.
        /// </summary>
        /// <exception cref="ArgumentException">If the general message does not have protection.</exception>
        /// <param name="pkiMessage">The General message</param>
        public ProtectedPkiMessage(GeneralPkiMessage pkiMessage)
        {
            if (!pkiMessage.HasProtection)
                throw new ArgumentException("GeneralPkiMessage not protected");

            this.m_pkiMessage = pkiMessage.ToAsn1Structure();
        }

        // TODO[cmp] Make internal? (Has test that uses it)
        /// <summary>
        /// Wrap a PKI message.
        /// </summary>
        /// <exception cref="ArgumentException">If the PKI message does not have protection.</exception>
        /// <param name="pkiMessage">The PKI message</param>
        public ProtectedPkiMessage(PkiMessage pkiMessage)
        {
            if (null == pkiMessage.Header.ProtectionAlg)
                throw new ArgumentException("PkiMessage not protected");

            this.m_pkiMessage = pkiMessage;
        }

        /// <summary>Message header</summary>
        public virtual PkiHeader Header => m_pkiMessage.Header;

        /// <summary>Message body</summary>
        public virtual PkiBody Body => m_pkiMessage.Body;

        /// <summary>
        /// Return the underlying ASN.1 structure contained in this object.
        /// </summary>
        /// <returns>PkiMessage structure</returns>
        public virtual PkiMessage ToAsn1Message() => m_pkiMessage;

        /// <summary>
        /// Determine whether the message is protected by a password based MAC. Use verify(PKMACBuilder, char[])
        /// to verify the message if this method returns true.
        /// </summary>
        /// <returns>true if protection MAC PBE based, false otherwise.</returns>
        public virtual bool HasPasswordBasedMacProtected
        {
            get { return CmpObjectIdentifiers.passwordBasedMac.Equals(Header.ProtectionAlg.Algorithm); }
        }

        /// <summary>
        /// Return the extra certificates associated with this message.
        /// </summary>
        /// <returns>an array of extra certificates, zero length if none present.</returns>
        public virtual X509Certificate[] GetCertificates()
        {
            CmpCertificate[] certs = m_pkiMessage.GetExtraCerts();
            if (null == certs)
                return new X509Certificate[0];

            X509Certificate[] result = new X509Certificate[certs.Length];
            for (int t = 0; t < certs.Length; t++)
            {
                result[t] = new X509Certificate(certs[t].X509v3PKCert);
            }
            return result;
        }

        /// <summary>
        /// Verify a message with a public key based signature attached.
        /// </summary>
        /// <param name="verifierFactory">a factory of signature verifiers.</param>
        /// <returns>true if the provider is able to create a verifier that validates the signature, false otherwise.</returns>      
        public virtual bool Verify(IVerifierFactory verifierFactory)
        {
            IStreamCalculator<IVerifier> streamCalculator = verifierFactory.CreateCalculator();

            IVerifier result = Process(streamCalculator);

            return result.IsVerified(m_pkiMessage.Protection.GetBytes());
        }

        /// <summary>
        /// Verify a message with password based MAC protection.
        /// </summary>
        /// <param name="pkMacBuilder">MAC builder that can be used to construct the appropriate MacCalculator</param>
        /// <param name="password">the MAC password</param>
        /// <returns>true if the passed in password and MAC builder verify the message, false otherwise.</returns>
        /// <exception cref="InvalidOperationException">if algorithm not MAC based, or an exception is thrown verifying the MAC.</exception>
        public virtual bool Verify(PKMacBuilder pkMacBuilder, char[] password)
        {
            if (!CmpObjectIdentifiers.passwordBasedMac.Equals(m_pkiMessage.Header.ProtectionAlg.Algorithm))
                throw new InvalidOperationException("protection algorithm is not mac based");

            PbmParameter parameter = PbmParameter.GetInstance(m_pkiMessage.Header.ProtectionAlg.Parameters);

            pkMacBuilder.SetParameters(parameter);

            IBlockResult result = Process(pkMacBuilder.Build(password).CreateCalculator());

            return Arrays.FixedTimeEquals(result.Collect(), m_pkiMessage.Protection.GetBytes());
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual bool Verify(PKMacBuilder pkMacBuilder, ReadOnlySpan<char> password)
        {
            if (!CmpObjectIdentifiers.passwordBasedMac.Equals(m_pkiMessage.Header.ProtectionAlg.Algorithm))
                throw new InvalidOperationException("protection algorithm is not mac based");

            PbmParameter parameter = PbmParameter.GetInstance(m_pkiMessage.Header.ProtectionAlg.Parameters);

            pkMacBuilder.SetParameters(parameter);

            IBlockResult result = Process(pkMacBuilder.Build(password).CreateCalculator());

            return Arrays.FixedTimeEquals(result.Collect(), m_pkiMessage.Protection.GetBytes());
        }
#endif

        private TResult Process<TResult>(IStreamCalculator<TResult> streamCalculator)
        {
            Asn1EncodableVector avec = new Asn1EncodableVector();
            avec.Add(m_pkiMessage.Header);
            avec.Add(m_pkiMessage.Body);
            byte[] enc = new DerSequence(avec).GetDerEncoded();

            using (var stream = streamCalculator.Stream)
            {
                stream.Write(enc, 0, enc.Length);
            }

            return streamCalculator.GetResult();
        }
    }
}
