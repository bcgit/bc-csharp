using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// A PKCS#10 certification request that is signed after it has been created (delay signing).
    /// </summary>
    /// <remarks>
    /// This is an extension of <see cref="Pkcs10CertificationRequest"/>, useful for situations where the private key
    /// is in another environment and not directly accessible (for example an HSM). The first step creates the
    /// request, then <see cref="GetDataToSign"/> provides the data to be signed outside this object, and finally the
    /// signature is passed to <c>SignRequest</c> to complete the request. The ASN.1 structure is described in
    /// RFC 2986 and <see href="http://www.rsasecurity.com/rsalabs/node.asp?id=2132"/>:
    /// <code>
    /// CertificationRequest ::= Sequence {
    ///   certificationRequestInfo  CertificationRequestInfo,
    ///   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
    ///   signature                 BIT STRING
    /// }
    ///
    /// CertificationRequestInfo ::= Sequence {
    ///   version             Integer { v1(0) } (v1,...),
    ///   subject             Name,
    ///   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    ///   attributes          [0] Attributes{{ CRIAttributes }}
    ///  }
    ///
    ///  Attributes { ATTRIBUTE:IOSet } ::= Set OF Attr{{ IOSet }}
    ///
    ///  Attr { ATTRIBUTE:IOSet } ::= Sequence {
    ///    type    ATTRIBUTE.&amp;id({IOSet}),
    ///    values  Set SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
    ///  }
    /// </code>
    /// </remarks>
    public class Pkcs10CertificationRequestDelaySigned
        : Pkcs10CertificationRequest
    {
        /// <summary>Default constructor for subclasses.</summary>
        protected Pkcs10CertificationRequestDelaySigned()
            : base()
        {
        }

        /// <summary>Parse a request from its encoding.</summary>
        /// <param name="encoded">The encoded request.</param>
        public Pkcs10CertificationRequestDelaySigned(byte[] encoded)
            : base(encoded)
        {
        }

        /// <summary>Create a request from an ASN.1 sequence.</summary>
        /// <param name="seq">The CertificationRequest sequence.</param>
        public Pkcs10CertificationRequestDelaySigned(Asn1Sequence seq)
            : base(seq)
        {
        }

        /// <summary>Parse a request from a stream containing its encoding.</summary>
        /// <param name="input">The stream to read from.</param>
        public Pkcs10CertificationRequestDelaySigned(Stream input)
            : base(input)
        {
        }

        /// <summary>Create a request that is also signed immediately with the given key.</summary>
        /// <param name="signatureAlgorithm">Name of Sig Alg.</param>
        /// <param name="subject">The X509Name of the subject.</param>
        /// <param name="publicKey">Public key to be included in cert request.</param>
        /// <param name="attributes">Asn1Set of Attributes.</param>
        /// <param name="signingKey">Private key matching <paramref name="publicKey"/>.</param>
        public Pkcs10CertificationRequestDelaySigned(string signatureAlgorithm, X509Name subject,
            AsymmetricKeyParameter publicKey, Asn1Set attributes, AsymmetricKeyParameter signingKey)
            : base(signatureAlgorithm, subject, publicKey, attributes, signingKey)
        {
        }

        /// <summary>Create a request that is also signed immediately with the given key.</summary>
        /// <param name="signatureAlgorithm">Name of Sig Alg.</param>
        /// <param name="subject">The X509Name of the subject.</param>
        /// <param name="pubInfo">SubjectPublicKeyInfo to be included in cert request.</param>
        /// <param name="attributes">Asn1Set of Attributes.</param>
        /// <param name="signingKey">Private key matching <paramref name="pubInfo"/>.</param>
        public Pkcs10CertificationRequestDelaySigned(string signatureAlgorithm, X509Name subject,
            SubjectPublicKeyInfo pubInfo, Asn1Set attributes, AsymmetricKeyParameter signingKey)
            : base(signatureAlgorithm, subject, pubInfo, attributes, signingKey)
        {
        }

        /// <summary>
        /// Instantiate a Pkcs10CertificationRequest object with the necessary credentials.
        /// </summary>
        /// <param name="signatureAlgorithm">Name of Sig Alg.</param>
        /// <param name="subject">X509Name of subject eg OU="My unit." O="My Organisatioin" C="au" </param>
        /// <param name="publicKey">Public key to be included in cert request.</param>
        /// <param name="attributes">Asn1Set of Attributes.</param>
        /// <remarks>
        /// After the object is constructed use the <see cref="GetDataToSign"/> and finally the
        /// SignRequest methods to finalize the request.
        /// </remarks>
        public Pkcs10CertificationRequestDelaySigned(string signatureAlgorithm, X509Name subject,
            AsymmetricKeyParameter publicKey, Asn1Set attributes)
            : this(signatureAlgorithm, subject, GetPubInfo(publicKey), attributes)
        {
        }

        /// <summary>
        /// Instantiate a Pkcs10CertificationRequest object with the necessary credentials.
        /// </summary>
        /// <param name="signatureAlgorithm">Name of Sig Alg.</param>
        /// <param name="subject">X509Name of subject eg OU="My unit." O="My Organisatioin" C="au" </param>
        /// <param name="pubInfo">SubjectPublicKeyInfo to be included in cert request.</param>
        /// <param name="attributes">Asn1Set of Attributes.</param>
        /// <remarks>
        /// After the object is constructed use the <see cref="GetDataToSign"/> and finally the
        /// SignRequest methods to finalize the request.
        /// </remarks>
        public Pkcs10CertificationRequestDelaySigned(string signatureAlgorithm, X509Name subject,
            SubjectPublicKeyInfo pubInfo, Asn1Set attributes)
        {
            if (signatureAlgorithm == null)
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            if (subject == null)
                throw new ArgumentNullException(nameof(subject));
            if (pubInfo == null)
                throw new ArgumentNullException(nameof(pubInfo));

            if (!m_algorithms.TryGetValue(signatureAlgorithm, out var sigOid) &&
                !DerObjectIdentifier.TryFromID(signatureAlgorithm, out sigOid))
            {
                throw new ArgumentException("Unknown signature type requested");
            }

            if (m_noParams.Contains(sigOid))
            {
                this.sigAlgId = new AlgorithmIdentifier(sigOid);
            }
            else if (m_exParams.TryGetValue(signatureAlgorithm, out var explicitParameters))
            {
                this.sigAlgId = new AlgorithmIdentifier(sigOid, explicitParameters);
            }
            else
            {
                this.sigAlgId = new AlgorithmIdentifier(sigOid, DerNull.Instance);
            }

            this.reqInfo = new CertificationRequestInfo(subject, pubInfo, attributes);
        }

        /// <summary>Return the DER encoding of the data that has to be signed to complete the request.</summary>
        public byte[] GetDataToSign()
        {
            return reqInfo.GetDerEncoded();
        }

        /// <summary>Complete the request with a signature calculated over <see cref="GetDataToSign"/>.</summary>
        /// <param name="signedData">The signature value.</param>
        public void SignRequest(byte[] signedData)
        {
            //build the signature from the signed data
            sigBits = new DerBitString(signedData);
        }

        /// <summary>Complete the request with a signature calculated over <see cref="GetDataToSign"/>.</summary>
        /// <param name="signedData">The signature value.</param>
        public void SignRequest(DerBitString signedData)
        {
            //build the signature from the signed data
            sigBits = signedData;
        }

        private static SubjectPublicKeyInfo GetPubInfo(AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("expected public key", nameof(publicKey));

            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        }
    }
}
