namespace Org.BouncyCastle.Utilities.IO.Pem
{
    public class PemHeader
    {
        private readonly string m_name;
        private readonly string m_value;

        public PemHeader(string name, string val)
        {
            m_name = name;
            m_value = val;
        }

        public virtual string Name => m_name;

        public virtual string Value => m_value;

        public override int GetHashCode() => GetHashCode(m_name) + 31 * GetHashCode(m_value);

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is PemHeader that
                && Objects.Equals(this.m_name, that.m_name)
                && Objects.Equals(this.m_value, that.m_value);
        }

        private int GetHashCode(string s) => s == null ? 1 : s.GetHashCode();

        public override string ToString() => m_name + ":" + m_value;
    }
}
