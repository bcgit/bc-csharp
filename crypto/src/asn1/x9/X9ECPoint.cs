using System;

using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * class for describing an ECPoint as a Der object.
     */
    public class X9ECPoint
        : Asn1Encodable
    {
        private readonly Asn1OctetString m_encoding;

        private readonly ECCurve m_c;
        private ECPoint m_p;

        /// <summary>Create a new <see cref="X9ECPoint"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="compressed">true if compressed, false otherwise.</param>
        public X9ECPoint(ECPoint p, bool compressed)
        {
            m_c = p.Curve;
            m_p = p.Normalize();
            m_encoding = new DerOctetString(p.GetEncoded(compressed));
        }

        /// <summary>Create a new <see cref="X9ECPoint"/>.</summary>
        /// <param name="c">The c.</param>
        /// <param name="encoding">The encoding.</param>
        public X9ECPoint(ECCurve c, byte[] encoding)
            : this(c, DerOctetString.FromContents(encoding))
        {
        }

        /// <summary>Create a new <see cref="X9ECPoint"/>.</summary>
        /// <param name="c">The c.</param>
        /// <param name="s">The s.</param>
        public X9ECPoint(ECCurve c, Asn1OctetString s)
        {
            m_c = c ?? throw new ArgumentNullException(nameof(c));
            m_p = null;
            m_encoding = s ?? throw new ArgumentNullException(nameof(s));
        }

        /// <summary>Return the point encoding.</summary>
        public byte[] GetPointEncoding() => Arrays.Clone(m_encoding.GetOctets());

        /// <summary>Gets the point encoding.</summary>
        public Asn1OctetString PointEncoding => m_encoding;

        /// <summary>Gets the point.</summary>
        public ECPoint Point => Objects.EnsureSingletonInitialized(ref m_p, this, self => self.CreatePoint());

        /// <summary>Gets a value indicating whether this is point compressed.</summary>
        public bool IsPointCompressed
        {
            get
            {
                byte[] octets = m_encoding.GetOctets();
                return octets.Length > 0 && (octets[0] == 2 || octets[0] == 3);
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  ECPoint ::= OCTET STRING
         * </pre>
         * <p>
         * Octet string produced using ECPoint.GetEncoded().</p>
         */
        public override Asn1Object ToAsn1Object() => m_encoding;

        private ECPoint CreatePoint() => m_c.DecodePoint(m_encoding.GetOctets());
    }
}
