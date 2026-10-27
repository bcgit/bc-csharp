using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>A key (and its bag attributes) held in a PKCS#12 store.</summary>
    public class AsymmetricKeyEntry
        : Pkcs12Entry
    {
        private readonly AsymmetricKeyParameter m_key;

        /// <summary>Create an entry for the given key, with no attributes.</summary>
        /// <param name="key">The key to hold.</param>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
        public AsymmetricKeyEntry(AsymmetricKeyParameter key)
            : base(new Dictionary<DerObjectIdentifier, Asn1Encodable>())
        {
            m_key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>Create an entry for the given key, with the given bag attributes.</summary>
        /// <param name="key">The key to hold.</param>
        /// <param name="attributes">The bag attributes, keyed by attribute object identifier.</param>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
        public AsymmetricKeyEntry(AsymmetricKeyParameter key,
            IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
            : base(attributes)
        {
            m_key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>Gets the key held by this entry.</summary>
        public AsymmetricKeyParameter Key => m_key;

        /// <summary>Two entries are equal if they hold equal keys; the attributes are not compared.</summary>
        public override bool Equals(object obj) => obj is AsymmetricKeyEntry that && m_key.Equals(that.m_key);

        /// <summary>Returns a hash code derived from the key.</summary>
        public override int GetHashCode() => ~m_key.GetHashCode();
    }
}
