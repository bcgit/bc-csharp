using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>General purpose writer for OpenSSL PEM objects.</summary>
    public class PemWriter
        : Utilities.IO.Pem.PemWriter
    {
        /// <summary>Create a writer.</summary>
        /// <param name="writer">The TextWriter object to write the output to.</param>
        public PemWriter(TextWriter writer)
            : base(writer)
        {
        }

        /// <summary>Write an object, unencrypted, in the PEM format used by OpenSSL.</summary>
        /// <param name="obj">
        /// The object to write: a key, key pair, certificate, CRL, request or other supported type.
        /// </param>
        /// <exception cref="IOException">The object could not be written.</exception>
        public void WriteObject(object obj)
        {
            WriteObject(obj, null, null, null);
        }

        /// <summary>Write an object, optionally encrypted, in the PEM format used by OpenSSL.</summary>
        /// <param name="obj">
        /// The object to write: a key, key pair, certificate, CRL, request or other supported type.
        /// </param>
        /// <param name="algorithm">The encryption algorithm to use, or null to write the object unencrypted.</param>
        /// <param name="password">The password to encrypt with; required if an algorithm is given.</param>
        /// <param name="random">The source of randomness for the encryption, or null to use the default.</param>
        /// <exception cref="IOException">The object could not be written.</exception>
        public void WriteObject(object obj, string algorithm, char[] password, SecureRandom random)
        {
            try
            {
                base.WriteObject(new MiscPemGenerator(obj, algorithm, password, random));
            }
            catch (PemGenerationException e)
            {
                if (e.InnerException is IOException inner)
                    throw inner;

                throw;
            }
        }
    }
}
