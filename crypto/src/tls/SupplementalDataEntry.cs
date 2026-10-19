using System;

namespace Org.BouncyCastle.Tls
{
    public sealed class SupplementalDataEntry
    {
        private readonly int m_dataType;
        private readonly byte[] m_data;

        /// <summary>Create a new <see cref="SupplementalDataEntry"/>.</summary>
        /// <param name="dataType">The data type.</param>
        /// <param name="data">The data.</param>
        public SupplementalDataEntry(int dataType, byte[] data)
        {
            this.m_dataType = dataType;
            this.m_data = data;
        }

        /// <summary>Gets the data type.</summary>
        public int DataType
        {
            get { return m_dataType; }
        }

        /// <summary>Gets the data.</summary>
        public byte[] Data
        {
            get { return m_data; }
        }
    }
}
