using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * an object for the elements in the X.509 V3 extension block.
     */
    public class X509Extension
    {
        private readonly bool m_critical;
        private readonly Asn1OctetString m_value;

        public X509Extension(DerBoolean critical, Asn1OctetString value)
        {
            m_critical = critical?.IsTrue ?? throw new ArgumentNullException(nameof(critical));
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public X509Extension(bool critical, Asn1OctetString value)
        {
            m_critical = critical;
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public bool IsCritical => m_critical;

        public Asn1OctetString Value => m_value;

        public Asn1Object GetParsedValue() => ConvertValueToObject(this);

        public override int GetHashCode()
        {
            int vh = Value.GetHashCode();

            return IsCritical ? vh : ~vh;
        }

        public override bool Equals(object obj)
        {
            return obj is X509Extension that
                && this.Value.Equals(that.Value)
                && this.IsCritical == that.IsCritical;
        }

        /// <sumary>Convert the value of the passed in extension to an object.</sumary>
        /// <param name="ext">The extension to parse.</param>
        /// <returns>The object the value string contains.</returns>
        /// <exception cref="ArgumentException">If conversion is not possible.</exception>
        public static Asn1Object ConvertValueToObject(X509Extension ext) => Extension.ConvertValueToObject(ext.Value);
    }
}
