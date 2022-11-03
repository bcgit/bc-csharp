namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    internal class KMatrices
    {
        private int nmatrices;
        private int rows;
        private int columns;
        private uint[] data;

        internal KMatrices(int nmatrices, int rows, int columns, uint[] data)
        {
            this.nmatrices = nmatrices;
            this.rows = rows;
            this.columns = columns;
            this.data = data;
        }

        internal int GetNmatrices()
        {
            return nmatrices;
        }

        internal int GetSize()
        {
            return rows * columns;
        }

        internal int GetRows()
        {
            return rows;
        }

        internal int GetColumns()
        {
            return columns;
        }

        internal uint[] GetData()
        {
            return data;
        }
    }

    internal class KMatricesWithPointer
        : KMatrices
    {
        private int matrixPointer;

        internal int GetMatrixPointer()
        {
            return matrixPointer;
        }

        internal void SetMatrixPointer(int matrixPointer)
        {
            this.matrixPointer = matrixPointer;
        }

        internal KMatricesWithPointer(KMatrices m)
            : base(m.GetNmatrices(), m.GetRows(), m.GetColumns(), m.GetData())
        {
            this.matrixPointer = 0;
        }
    }
}
