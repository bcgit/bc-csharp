using System;
using System.IO;
using System.Text;

namespace crypto.openpgp
{
    /**
     * Writer for S-expression keys
     * <p>
     * Format documented here:
     * http://people.csail.mit.edu/rivest/Sexp.txt
     * 
     * Only canonical S expression format is used.
     * </p>
     */
    class SXprWriter
    {
        Stream output;

        public SXprWriter(Stream output)
        {
            this.output = output;
        }

        public void StartList()
        {
            output.WriteByte((byte)'(');
        }

        public void EndList()
        {
            output.WriteByte((byte)')');
        }

        public void WriteString(string s)
        {
            byte[] stringBytes = Encoding.UTF8.GetBytes(s);
            byte[] lengthBytes = Encoding.UTF8.GetBytes(stringBytes.Length + ":");
            output.Write(lengthBytes, 0, lengthBytes.Length);
            output.Write(stringBytes, 0, stringBytes.Length);
        }

        public void WriteBytes(byte[] b)
        {
            byte[] lengthBytes = Encoding.UTF8.GetBytes(b.Length + ":");
            output.Write(lengthBytes, 0, lengthBytes.Length);
            output.Write(b, 0, b.Length);
        }
    }
}
