using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
    /// <summary>A holding class for constructing an X509 Key Usage extension.</summary>
    /// <remarks>
    /// <code>
    /// id-ce - keyUsage OBJECT IDENTIFIER ::=  { id - ce 15 }
    ///
    /// KeyUsage ::= BIT STRING {
    ///     digitalSignature(0),
    ///     nonRepudiation(1),
    ///     keyEncipherment(2),
    ///     dataEncipherment(3),
    ///     keyAgreement(4),
    ///     keyCertSign(5),
    ///     cRLSign(6),
    ///     encipherOnly(7),
    ///     decipherOnly(8) }
    /// </code>
    /// </remarks>
    public class X509KeyUsage
        : Asn1Encodable
    {
        /// <summary>The key may be used for digital signatures.</summary>
        public const int DigitalSignature = 1 << 7;
        /// <summary>The key may be used for non-repudiation (content commitment).</summary>
        public const int NonRepudiation = 1 << 6;
        /// <summary>The key may be used to encipher other keys.</summary>
        public const int KeyEncipherment = 1 << 5;
        /// <summary>The key may be used to encipher data directly.</summary>
        public const int DataEncipherment = 1 << 4;
        /// <summary>The key may be used for key agreement.</summary>
        public const int KeyAgreement = 1 << 3;
        /// <summary>The key may be used to sign certificates.</summary>
        public const int KeyCertSign = 1 << 2;
        /// <summary>The key may be used to sign CRLs.</summary>
        public const int CrlSign = 1 << 1;
        /// <summary>With key agreement, the key may only be used to encipher data.</summary>
        public const int EncipherOnly = 1 << 0;
        /// <summary>With key agreement, the key may only be used to decipher data.</summary>
        public const int DecipherOnly = 1 << 15;

        private readonly int m_usage;

        /// <summary>Create a key usage extension value.</summary>
        /// <param name="usage">
        /// The bitwise OR of the Key Usage flags giving the allowed uses for the key.
        /// e.g. (X509KeyUsage.keyEncipherment | X509KeyUsage.dataEncipherment).
        /// </param>
        public X509KeyUsage(int usage)
        {
            m_usage = usage;
        }

        /// <summary>Return the ASN.1 KeyUsage structure for the usage flags.</summary>
        public override Asn1Object ToAsn1Object() => new KeyUsage(m_usage);
    }
}
