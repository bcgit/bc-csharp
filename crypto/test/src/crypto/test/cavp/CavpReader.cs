using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Policy;
using NUnit.Framework.Constraints;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests.Cavp
{

    public class Vector : Hashtable
    {
        public Hashtable Header { get; set; }

        public string ValueAsString(string name)
        {
            return this[name] as string;
        }

        public string HeaderAsString(string name)
        {
            return Header[name] as string;
        }

        public byte[] ValueAsBytes(string name)
        {
            string value = this[name] as string;
            if (value != null)
            {
                return Hex.Decode(value);
            }

            return null;
        }

        public byte[] HeaderAsBytes(string name)
        {
            string value = Header[name] as string;
            if (value != null)
            {
                return Hex.Decode(value);
            }

            return null;
        }

        public int ValueAsInt(string name, int? def = null)
        {
            string value = this[name] as string;
            if (value == null)
            {
                if (def != null)
                {
                    return (int)def;
                }
                throw new InvalidOperationException(name + " was null");
            }
            return Int32.Parse(value);
        }

    }


    public class CavpReader
    {

        public static ArrayList readVectorFile(string file)
        {
            //
            // Build path
            //

            string deployDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            string[] pathParts = new string[] { "..", "..", "test", "data", "crypto", "cavp" };
            string vectorDir = "";
            foreach (string pathPart in pathParts)
            {
                vectorDir += pathPart;
                vectorDir += Path.DirectorySeparatorChar;
            }

            string vectorFile = Path.GetFullPath(Path.Combine(vectorDir, file));
            string[] lines = File.ReadAllLines(vectorFile);
            ArrayList vectors = new ArrayList();
            Hashtable header = null;
            Vector currentVector = null;


            int headerState = 0;


            foreach (string line in lines)
            {
                // Reading a header or waiting to encounter a header
                // and we encounter a vector line.
                // Set up a new vector.
                if (headerState <= 1 && !line.StartsWith("[") && line.Contains("="))
                {
                    currentVector = new Vector() { Header = header };
                    vectors.Add(currentVector);
                    headerState = 2;
                }

                //
                // Read
                //
                if (headerState == 2)
                {
                    //
                    // Header line found immediately after vector elements.
                    //
                    if (line.StartsWith("[") && line.EndsWith("]"))
                    {
                        headerState = 0;
                    }
                    else

                    //
                    // Not a valid line so we assume this is a break between vectors.
                    //
                    if (headerState == 2 && !line.Contains("="))
                    {
                        headerState = 0;
                    }
                    else

                    //
                    // Vector parameter.
                    //
                    if (!line.StartsWith("[") && line.Contains("="))
                    {
                        if (currentVector == null)
                        {
                            currentVector = new Vector() { Header = header };
                            vectors.Add(currentVector);
                        }


                        string[] parts = line.Split('=');
                        currentVector[parts[0].Trim()] = parts[1].Trim();
                        headerState = 2;
                    }
                }

                //
                // Found start of header block.
                // We need a new header map.
                //
                if (headerState == 0 && line.StartsWith("[") && line.EndsWith("]"))
                {
                    header = new Hashtable();
                    headerState = 1;
                }

                //
                // Read header lines.
                //
                if (headerState <= 1)
                {
                    if (line.StartsWith("[") && line.EndsWith("]"))
                    {
                        // Strip away brackets.
                        string trimmed = line.Substring(1, line.Length - 2);
                        string[] parts = trimmed.Split('=');
                        header[parts[0].Trim()] = parts[1].Trim();
                        headerState = 1;
                    }
                }
            }


            return vectors;
        }








        public static IMac CreatePRF(Vector config)
        {
            IMac prf;
            string type = config.HeaderAsString("PRF");
            if (type == null)
            {
                throw new ArgumentException("prf field was null.");
            }

            if (type.StartsWith("CMAC_AES"))
            {
                IBlockCipher blockCipher = new AesEngine();
                prf = new CMac(blockCipher);
            }
            else if (type.StartsWith("CMAC_TDES"))
            {
                IBlockCipher blockCipher = new DesEdeEngine();
                prf = new CMac(blockCipher);
            }
            else if (type.StartsWith("HMAC_SHA1"))
            {
                IDigest digest = new Sha1Digest();
                prf = new HMac(digest);
            }
            else if (type.StartsWith("HMAC_SHA224"))
            {
                IDigest digest = new Sha224Digest();
                prf = new HMac(digest);
            }
            else if (type.StartsWith("HMAC_SHA256"))
            {
                IDigest digest = new Sha256Digest();
                prf = new HMac(digest);
            }
            else if (type.StartsWith("HMAC_SHA384"))
            {
                IDigest digest = new Sha384Digest();
                prf = new HMac(digest);
            }
            else if (type.StartsWith("HMAC_SHA512"))
            {
                IDigest digest = new Sha512Digest();
                prf = new HMac(digest);
            }
            else
            {
                throw new ArgumentException("Unknown Mac for PRF " + type);
            }
            return prf;
        }

    }
}