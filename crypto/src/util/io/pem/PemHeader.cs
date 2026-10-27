namespace Org.BouncyCastle.Utilities.IO.Pem
{
    /// <summary>A header (a name and value pair) of a PEM object.</summary>
    public class PemHeader
    {
        private readonly string m_name;
        private readonly string m_value;

        /// <summary>Create a new <see cref="PemHeader"/>.</summary>
        /// <param name="name">The name.</param>
        /// <param name="val">The val.</param>
        public PemHeader(string name, string val)
        {
            m_name = name;
            m_value = val;
        }

        /// <summary>Gets the name.</summary>
        public virtual string Name => m_name;

        /// <summary>Gets the value.</summary>
        public virtual string Value => m_value;

        /// <inheritdoc/>
        public override int GetHashCode() => GetHashCode(m_name) + 31 * GetHashCode(m_value);

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is PemHeader that
                && Objects.Equals(this.m_name, that.m_name)
                && Objects.Equals(this.m_value, that.m_value);
        }

        private int GetHashCode(string s) => s == null ? 1 : s.GetHashCode();

        /// <inheritdoc/>
        public override string ToString() => m_name + ":" + m_value;
    }
}
