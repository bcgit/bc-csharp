using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
    /// <summary>Class for carrying the values in an X.509 Attribute.</summary>
    public class X509Attribute
        : Asn1Encodable
    {
        private readonly AttributeX509 m_attr;

        internal X509Attribute(Asn1Encodable at)
        {
            m_attr = AttributeX509.GetInstance(at);
        }

        /// <summary>
        /// Create an X.509 Attribute with the type given by <paramref name="oid"/> and the value represented by an
        /// ASN.1 Set containing <paramref name="value"/>.
        /// </summary>
        /// <param name="oid">Type of the attribute.</param>
        /// <param name="value">The object to go into the atribute's value set.</param>
        public X509Attribute(string oid, Asn1Encodable value)
        {
            m_attr = new AttributeX509(new DerObjectIdentifier(oid), new DerSet(value));
        }

        /// <summary>
        /// Create an X.509 Attribute with the type given by <paramref name="oid"/> and the value represented by an
        /// ASN.1 Set containing the objects in <paramref name="value"/>.
        /// </summary>
        /// <param name="oid">Type of the attribute.</param>
        /// <param name="value">Vector of values to go into the atribute's value set.</param>
        public X509Attribute(string oid, Asn1EncodableVector value)
        {
            m_attr = new AttributeX509(new DerObjectIdentifier(oid), DerSet.FromVector(value));
        }

        public string Oid => m_attr.AttrType.GetID();

        public Asn1Encodable[] GetValues() => m_attr.AttrValues.ToArray();

        public override Asn1Object ToAsn1Object() => m_attr.ToAsn1Object();
    }
}
