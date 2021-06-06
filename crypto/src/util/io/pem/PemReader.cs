using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	public class PemReader
	{
		private const string BeginString = "-----BEGIN ";
		private const string EndString = "-----END ";

		private readonly TextReader reader;

		public PemReader(TextReader reader)
		{
			if (reader == null)
				throw new ArgumentNullException("reader");

			this.reader = reader;
		}

		public TextReader Reader
		{
			get { return reader; }
		}

		/// <returns>
		/// A <see cref="PemObject"/>
		/// </returns>
		/// <exception cref="IOException"></exception>
		public PemObject ReadPemObject()
		{
            string line = reader.ReadLine();

            while (line != null && !Platform.StartsWith(line, BeginString)) 
            {
                line = reader.ReadLine();
            }

            if (line != null)
            {
                line = line.Substring(BeginString.Length);
                int index = line.IndexOf('-');

                if (index > 0 && Platform.EndsWith(line, "-----") && (line.Length - index) == 5)
                {
                    string type = line.Substring(0, index);

                    return LoadObject(type);
                }
            }

            return null;
		}

		private PemObject LoadObject(string type)
		{
			string endMarker = EndString + type;
			IList headers = Platform.CreateArrayList();
			StringBuilder buf = new StringBuilder();

			string line;
			while ((line = reader.ReadLine()) != null)
			{
				int colonPos = line.IndexOf(':');
				if (colonPos >= 0)
				{
                    string hdr = line.Substring(0, colonPos).Trim();
                    string val = line.Substring(colonPos + 1).Trim();

                    headers.Add(new PemHeader(hdr, val));
                    continue;
				}

                if (Platform.IndexOf(line, endMarker) >= 0)
                    break;

                buf.Append(line.Trim());
            }

            if (line == null)
				throw new IOException(endMarker + " not found");

			return new PemObject(type, headers, Base64.Decode(buf.ToString()));
		}
	}
}
