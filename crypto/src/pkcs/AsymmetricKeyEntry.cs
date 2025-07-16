using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{
    public class AsymmetricKeyEntry
        : Pkcs12Entry
    {
        private readonly AsymmetricKeyParameter m_key;

        public AsymmetricKeyEntry(AsymmetricKeyParameter key)
            : base(new Dictionary<DerObjectIdentifier, Asn1Encodable>())
        {
            m_key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public AsymmetricKeyEntry(AsymmetricKeyParameter key,
            IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
            : base(attributes)
        {
            m_key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public AsymmetricKeyParameter Key => m_key;

        public override bool Equals(object obj) => obj is AsymmetricKeyEntry that && m_key.Equals(that.m_key);

        public override int GetHashCode() => ~m_key.GetHashCode();
    }
}
