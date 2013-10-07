using System.Text;

namespace Org.BouncyCastle.Asn1.X500.Style
{

    /**
     * class for breaking up an X500 Name into it's component tokens, ala
     * java.util.StringTokenizer. We need this class as some of the
     * lightweight Java environment don't support classes like
     * StringTokenizer.
     */
    class X500NameTokenizer
    {
        private string value;
        private int index;
        private char separator;
        private StringBuilder buf = new StringBuilder();

        public X500NameTokenizer(string oid)
            : this(oid, ',')
        {
            
        }

        public X500NameTokenizer(
            string oid,
            char separator)
        {
            this.value = oid;
            this.index = -1;
            this.separator = separator;
        }

        public bool hasMoreTokens()
        {
            return (index != value.Length);
        }

        public string nextToken()
        {
            if (index == value.Length)
            {
                return null;
            }

            int end = index + 1;
            bool quoted = false;
            bool escaped = false;

            buf.Length = 0;

            while (end != value.Length)
            {
                char c = value[end];

                if (c == '"')
                {
                    if (!escaped)
                    {
                        quoted = !quoted;
                    }
                    buf.Append(c);
                    escaped = false;
                }
                else
                {
                    if (escaped || quoted)
                    {
                        buf.Append(c);
                        escaped = false;
                    }
                    else if (c == '\\')
                    {
                        buf.Append(c);
                        escaped = true;
                    }
                    else if (c == separator)
                    {
                        break;
                    }
                    else
                    {
                        buf.Append(c);
                    }
                }
                end++;
            }

            index = end;

            return buf.ToString();
        }
    }
}