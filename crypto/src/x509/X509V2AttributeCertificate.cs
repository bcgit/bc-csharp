using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;

namespace Org.BouncyCastle.X509
{
    /// <summary>An implementation of a version 2 X.509 Attribute Certificate.</summary>
    public class X509V2AttributeCertificate
        : X509ExtensionBase
    {
        private readonly AttributeCertificate m_cert;
        private readonly DateTime m_notBefore;
        private readonly DateTime m_notAfter;

        private static AttributeCertificate GetObject(Stream input)
        {
            try
            {
                return AttributeCertificate.GetInstance(Asn1Object.FromStream(input));
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new IOException("exception decoding certificate structure", e);
            }
        }

        /// <summary>Parse an attribute certificate from a stream.</summary>
        /// <param name="encIn">A stream positioned at the encoded certificate.</param>
        /// <exception cref="IOException">The certificate cannot be decoded.</exception>
        public X509V2AttributeCertificate(Stream encIn)
            : this(GetObject(encIn))
        {
        }

        /// <summary>Parse an attribute certificate from its encoding.</summary>
        /// <param name="encoded">The encoded certificate.</param>
        /// <exception cref="IOException">The certificate cannot be decoded.</exception>
        public X509V2AttributeCertificate(byte[] encoded)
            : this(new MemoryStream(encoded, false))
        {
        }

        /// <summary>Wrap an ASN.1 AttributeCertificate structure.</summary>
        /// <param name="cert">The ASN.1 structure.</param>
        /// <exception cref="IOException">The validity period cannot be read.</exception>
        public X509V2AttributeCertificate(AttributeCertificate cert)
        {
            m_cert = cert;

            try
            {
                m_notAfter = cert.ACInfo.AttrCertValidityPeriod.NotAfterTime.ToDateTime();
                m_notBefore = cert.ACInfo.AttrCertValidityPeriod.NotBeforeTime.ToDateTime();
            }
            catch (Exception e)
            {
                throw new IOException("invalid data structure in certificate!", e);
            }
        }

        /// <summary>Gets the underlying ASN.1 structure.</summary>
        public virtual AttributeCertificate AttributeCertificate => m_cert;

        /// <summary>Gets the version number of the attribute certificate.</summary>
        public virtual int Version => m_cert.ACInfo.Version.IntValueExact + 1;

        /// <summary>Gets the serial number of the attribute certificate.</summary>
        public virtual BigInteger SerialNumber => m_cert.ACInfo.SerialNumber.Value;

        /// <summary>Gets the holder of the attribute certificate.</summary>
        public virtual AttributeCertificateHolder Holder =>
            new AttributeCertificateHolder((Asn1Sequence)m_cert.ACInfo.Holder.ToAsn1Object());

        /// <summary>Gets the issuer of the attribute certificate.</summary>
        public virtual AttributeCertificateIssuer Issuer => new AttributeCertificateIssuer(m_cert.ACInfo.Issuer);

        /// <summary>Gets the start of the validity period.</summary>
        public virtual DateTime NotBefore => m_notBefore;

        /// <summary>Gets the end of the validity period.</summary>
        public virtual DateTime NotAfter => m_notAfter;

        /// <summary>Return the issuer unique ID as an array of bits, or null if there is none.</summary>
        public virtual bool[] GetIssuerUniqueID()
        {
            DerBitString id = m_cert.ACInfo.IssuerUniqueID;

            if (id != null)
            {
                byte[] bytes = id.GetBytes();
                bool[] boolId = new bool[bytes.Length * 8 - id.PadBits];

                for (int i = 0; i != boolId.Length; i++)
                {
                    boolId[i] = (bytes[i / 8] & (0x80 >> (i % 8))) != 0;
                }

                return boolId;
            }

            return null;
        }

        /// <summary>Gets whether the certificate is valid at the current time.</summary>
        public virtual bool IsValidNow => IsValid(DateTime.UtcNow);

        /// <summary>Return whether the certificate is valid at the given date.</summary>
        /// <param name="date">The date to check.</param>
        public virtual bool IsValid(DateTime date) =>
            date.CompareTo(NotBefore) >= 0 && date.CompareTo(NotAfter) <= 0;

        /// <summary>Check that the certificate is valid at the current time.</summary>
        /// <exception cref="CertificateExpiredException">The certificate has expired.</exception>
        /// <exception cref="CertificateNotYetValidException">The certificate is not yet valid.</exception>
        public virtual void CheckValidity() => CheckValidity(DateTime.UtcNow);

        /// <summary>Check that the certificate is valid at the given date.</summary>
        /// <param name="date">The date to check.</param>
        /// <exception cref="CertificateExpiredException">The certificate has expired.</exception>
        /// <exception cref="CertificateNotYetValidException">The certificate is not yet valid.</exception>
        public virtual void CheckValidity(DateTime date)
        {
            if (date.CompareTo(NotAfter) > 0)
                throw new CertificateExpiredException("certificate expired on " + NotAfter);
            if (date.CompareTo(NotBefore) < 0)
                throw new CertificateNotYetValidException("certificate not valid until " + NotBefore);
        }

        /// <summary>Gets the signature algorithm identifier.</summary>
        public virtual AlgorithmIdentifier SignatureAlgorithm => m_cert.SignatureAlgorithm;

        /// <summary>Return the signature octets.</summary>
        public virtual byte[] GetSignature() => m_cert.GetSignatureOctets();

        /// <summary>Check whether the certificate signature is valid for the given public key.</summary>
        /// <param name="key">The public key of the issuer.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CertificateException">The signature algorithms in the certificate do not match.</exception>
        // TODO[api] Rename 'key' to 'publicKey'
        public virtual bool IsSignatureValid(AsymmetricKeyParameter key) =>
            CheckSignatureValid(new Asn1VerifierFactory(m_cert.SignatureAlgorithm, key));

        /// <summary>Check whether the certificate signature is valid, using a verifier from the given provider.
        /// </summary>
        /// <param name="verifierProvider">A provider of signature verifier factories.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CertificateException">The signature algorithms in the certificate do not match.</exception>
        public virtual bool IsSignatureValid(IVerifierFactoryProvider verifierProvider) =>
            CheckSignatureValid(verifierProvider.CreateVerifierFactory(m_cert.SignatureAlgorithm));

        /// <summary>Verify the certificate signature with the given public key.</summary>
        /// <param name="key">The public key of the issuer.</param>
        /// <exception cref="InvalidKeyException">The certificate does not verify with the key.</exception>
        /// <exception cref="CertificateException">The signature algorithms in the certificate do not match.</exception>
        // TODO[api] Rename 'key' to 'publicKey'
        public virtual void Verify(AsymmetricKeyParameter key) =>
            CheckSignature(new Asn1VerifierFactory(m_cert.SignatureAlgorithm, key));

        /// <summary>
        /// Verify the certificate's signature using a verifier created using the passed in verifier provider.
        /// </summary>
        /// <param name="verifierProvider">An appropriate provider for verifying the certificate's signature.</param>
        /// <exception cref="InvalidKeyException">The certificate does not verify.</exception>
        /// <exception cref="CertificateException">The signature algorithms in the certificate do not match.</exception>
        public virtual void Verify(IVerifierFactoryProvider verifierProvider) =>
            CheckSignature(verifierProvider.CreateVerifierFactory(m_cert.SignatureAlgorithm));

        /// <summary>Verify the certificate signature using the given verifier factory.</summary>
        /// <param name="verifier">The verifier factory.</param>
        /// <exception cref="InvalidKeyException">The certificate does not verify.</exception>
        protected virtual void CheckSignature(IVerifierFactory verifier)
        {
            if (!CheckSignatureValid(verifier))
                throw new InvalidKeyException("Public key presented not for certificate signature");
        }

        /// <summary>Check the certificate signature using the given verifier factory.</summary>
        /// <param name="verifier">The verifier factory.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        /// <exception cref="CertificateException">The signature algorithms in the certificate do not match.</exception>
        protected virtual bool CheckSignatureValid(IVerifierFactory verifier)
        {
            var acInfo = m_cert.ACInfo;

            // TODO Compare IsAlgIDEqual in X509Certificate.CheckSignature
            if (!m_cert.SignatureAlgorithm.Equals(acInfo.Signature))
                throw new CertificateException("Signature algorithm in certificate info not same as outer certificate");

            return X509Utilities.VerifySignature(verifier, acInfo, m_cert.SignatureValue);
        }

        /// <summary>Return the encoded attribute certificate.</summary>
        public virtual byte[] GetEncoded() => m_cert.GetEncoded();

        /// <summary>Returns the extensions of the attribute certificate.</summary>
        protected override X509Extensions GetX509Extensions() => m_cert.ACInfo.Extensions;

        /// <summary>Return all the attributes in the certificate.</summary>
        public virtual X509Attribute[] GetAttributes() =>
            m_cert.ACInfo.Attributes.MapElements(element => new X509Attribute(element));

        /// <summary>Return the attributes in the certificate with the given type.</summary>
        /// <param name="oid">The object identifier of the attribute type.</param>
        /// <returns>The matching attributes, or null if there are none.</returns>
        public virtual X509Attribute[] GetAttributes(string oid)
        {
            Asn1Sequence seq = m_cert.ACInfo.Attributes;
            var list = new List<X509Attribute>();

            for (int i = 0; i != seq.Count; i++)
            {
                X509Attribute attr = new X509Attribute((Asn1Encodable)seq[i]);
                if (attr.Oid.Equals(oid))
                {
                    list.Add(attr);
                }
            }

            if (list.Count < 1)
                return null;

            return list.ToArray();
        }

        /// <summary>Two attribute certificates are equal if their underlying ASN.1 structures are equal.</summary>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is X509V2AttributeCertificate that
                && this.m_cert.Equals(that.m_cert);

            // NB: May prefer this implementation of Equals if more than one certificate implementation in play
            //Arrays.AreEqual(this.GetEncoded(), other.GetEncoded());
        }

        /// <summary>Returns a hash code derived from the underlying ASN.1 structure.</summary>
        public override int GetHashCode() => m_cert.GetHashCode();
    }
}
