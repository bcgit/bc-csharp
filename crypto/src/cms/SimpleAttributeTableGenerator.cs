using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Returns a fixed <see cref="AttributeTable"/> regardless of generation parameters. Used for unsigned attributes
    /// and other cases where attributes are fully preconfigured.
    /// </summary>
    public class SimpleAttributeTableGenerator
        : CmsAttributeTableGenerator
    {
        private readonly AttributeTable attributes;

        /// <summary>Creates a generator that always returns <paramref name="attributes"/>.</summary>
        /// <param name="attributes">The attribute table to return from <see cref="GetAttributes"/>.</param>
        public SimpleAttributeTableGenerator(
            AttributeTable attributes)
        {
            this.attributes = attributes;
        }

        /// <inheritdoc/>
        public virtual AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters)
        {
            return attributes;
        }
    }
}
