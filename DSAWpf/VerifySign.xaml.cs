
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Windows;
using System.Windows.Forms;

namespace DSAWpf
{
    /// <summary>
    /// Логика взаимодействия для Verify.xaml
    /// </summary>
    public partial class VerifySign : Window
    {
        string pathKey;
        string pathFile;
        string pathSign;
        public VerifySign()
        {
            InitializeComponent();
        }

        private void browseKey(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK) { pathKey = ofd.FileName; boxKey.Text = ofd.FileName; }
            else return;

        }
        private void browseFile(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                pathFile = ofd.FileName;
                boxFile.Text = ofd.FileName;
            }
            else
            {
                return;
            }
        }
        private void browseSign(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                pathSign = ofd.FileName;
                boxSign.Text = ofd.FileName;
            }
            else
            {
                return;
            }
        }

        private void Verify(object sender, RoutedEventArgs e)
        {
            byte[] BytesToSign;
            byte[] ExpectedSignatureBytes;
            using (FileStream fs = new FileStream(pathFile, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                fs.Close();
                BytesToSign = buffer;
            }
            using (FileStream token = new FileStream(pathSign, FileMode.Open, FileAccess.Read))
            {
                byte[] buff = new byte[token.Length];
                token.Read(buff, 0, buff.Length);
                token.Close();
                ExpectedSignatureBytes = buff;
            }

            TextReader reader = File.OpenText(pathKey);
            AsymmetricKeyParameter KeyPair = (AsymmetricKeyParameter)new PemReader(reader).ReadObject();

            Sha256Digest sha256Digest = new Sha256Digest();
            byte[] TheHash = new byte[sha256Digest.GetDigestSize()];
            sha256Digest.BlockUpdate(BytesToSign, 0, BytesToSign.Length);
            sha256Digest.DoFinal(TheHash, 0);

            PssSigner Signer = new PssSigner(new RsaEngine(), new Sha256Digest(), sha256Digest.GetDigestSize());
            Signer.Init(false, KeyPair);
            Signer.BlockUpdate(TheHash, 0, TheHash.Length);
            if (Signer.VerifySignature(ExpectedSignatureBytes)) System.Windows.MessageBox.Show("VerifySignature == OK");
            else System.Windows.MessageBox.Show("VerifySignature != OK");
            Close();
        }
    }
}
