namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The KeyUsage object.
     * <pre>
     *    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     *
     *    KeyUsage ::= BIT STRING {
     *         digitalSignature        (0),
     *         nonRepudiation          (1),
     *         keyEncipherment         (2),
     *         dataEncipherment        (3),
     *         keyAgreement            (4),
     *         keyCertSign             (5),
     *         cRLSign                 (6),
     *         encipherOnly            (7),
     *         decipherOnly            (8) }
     * </pre>
     */
    public class KeyUsage
        : DerBitString
    {
        /// <summary>The digitalSignature key usage bit.</summary>
        public const int DigitalSignature = (1 << 7);
        /// <summary>The nonRepudiation (contentCommitment) key usage bit.</summary>
        public const int NonRepudiation   = (1 << 6);
        /// <summary>The keyEncipherment key usage bit.</summary>
        public const int KeyEncipherment  = (1 << 5);
        /// <summary>The dataEncipherment key usage bit.</summary>
        public const int DataEncipherment = (1 << 4);
        /// <summary>The keyAgreement key usage bit.</summary>
        public const int KeyAgreement     = (1 << 3);
        /// <summary>The keyCertSign key usage bit.</summary>
        public const int KeyCertSign      = (1 << 2);
        /// <summary>The cRLSign key usage bit.</summary>
        public const int CrlSign          = (1 << 1);
        /// <summary>The encipherOnly key usage bit.</summary>
        public const int EncipherOnly     = (1 << 0);
        /// <summary>The decipherOnly key usage bit.</summary>
        public const int DecipherOnly     = (1 << 15);

        /// <summary>Return an <see cref="KeyUsage"/> from the given object.</summary>
        /// <param name="obj">An <see cref="KeyUsage"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="KeyUsage"/>, or null if <paramref name="obj"/> is null.</returns>
        public static new KeyUsage GetInstance(object obj)
        {
            if (obj is KeyUsage keyUsage)
                return keyUsage;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
            if (obj == null)
                return null;
            return new KeyUsage(DerBitString.GetInstance(obj));
        }

        /// <summary>Get the extension of this type from a table of extensions, if it is present.</summary>
        /// <param name="extensions">The extensions, or null.</param>
        /// <returns>The value, or null if the extension is not present.</returns>
        public static KeyUsage FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.KeyUsage));
        }

        /**
         * Basic constructor.
         *
         * @param usage - the bitwise OR of the Key Usage flags giving the
         * allowed uses for the key.
         * e.g. (KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)
         */
        public KeyUsage(int usage)
            : base(usage)
        {
        }

        private KeyUsage(
            DerBitString usage)
            : base(usage.GetBytes(), usage.PadBits)
        {
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            byte[] data = GetBytes();
            if (data.Length == 1)
            {
                return "KeyUsage: 0x" + (data[0] & 0xff).ToString("X");
            }

            return "KeyUsage: 0x" + ((data[1] & 0xff) << 8 | (data[0] & 0xff)).ToString("X");
        }
    }
}
