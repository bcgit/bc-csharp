namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /**
     * Class holding precomputation data for fixed-point multiplications.
     */
    public class FixedPointPreCompInfo
        : PreCompInfo
    {
        /**
         * Array holding the precomputed <code>ECPoint</code>s used for a fixed
         * point multiplication.
         */
        protected ECPoint[] m_preComp = null;

        public virtual ECPoint[] PreComp
        {
            get { return m_preComp; }
            set { this.m_preComp = value; }
        }
    }
}
