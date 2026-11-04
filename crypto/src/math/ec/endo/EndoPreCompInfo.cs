using System;

using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Math.EC.Endo
{
    /// <summary>Precomputation data for an endomorphism: the endomorphism and the mapped point.</summary>
    public class EndoPreCompInfo
        : PreCompInfo
    {
        /// <summary>The endomorphism.</summary>
        protected ECEndomorphism m_endomorphism;

        /// <summary>The mapped point.</summary>
        protected ECPoint m_mappedPoint;

        /// <summary>Gets or sets the endomorphism.</summary>
        public virtual ECEndomorphism Endomorphism
        {
            get { return m_endomorphism; }
            set { this.m_endomorphism = value; }
        }

        /// <summary>Gets or sets the mapped point.</summary>
        public virtual ECPoint MappedPoint
        {
            get { return m_mappedPoint; }
            set { this.m_mappedPoint = value; }
        }
    }
}
