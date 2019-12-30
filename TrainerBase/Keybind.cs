using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace pAutism
{
    public partial class Keybind : Form
    {
        public Keybind()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Hide();
            TopMost = false;
        }

        private void Keybind_MouseDown(object sender, MouseEventArgs e)
        {

        }


        private void hakList_MouseDown(object sender, MouseEventArgs e)
        {
            Control ctl = sender as Control;

            // when we get a buttondown message from a button control
            // the button has capture, we need to release capture so
            // or DragMe() won't work.
            ReleaseCapture(ctl.Handle);

            this.DragMe(); // put the form into mousedrag mode.
        }
        private void hakList_MouseMove(object sender, MouseEventArgs e)
        {

        }
        [DllImport("user32.dll")]
        static extern IntPtr DefWindowProc(IntPtr hWnd, uint uMsg, UIntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")]
        static extern bool ReleaseCapture(IntPtr hwnd);

        [DllImport("dwmapi.dll", PreserveSig = false)]
        public static extern int DwmEnableComposition(bool fEnable);


        const uint WM_SYSCOMMAND = 0x112;
        const uint MOUSE_MOVE = 0xF012;

        public void DragMe()
        {
            DefWindowProc(this.Handle, WM_SYSCOMMAND, (UIntPtr)MOUSE_MOVE, IntPtr.Zero);
        }
        private void Keybind_MouseMove(object sender, MouseEventArgs e)
        {

        }

        private void Keybind_MouseUp(object sender, MouseEventArgs e)
        {

        }

        private void hakList_MouseUp(object sender, MouseEventArgs e)
        {

        }

        private void Keybind_Load(object sender, EventArgs e)
        {
        }

        int biggest = 0;
        public async void Signal()
        {
            await Task.Delay(0);


            hakList.Items.Clear();
            ListView.ListViewItemCollection ffa = pAutism.fff.kk.hakList.Items;
            foreach (object obj in ffa)
            {
                ListViewItem dummy = (ListViewItem)obj; //parse

                hakList.Items.Add(dummy.Text);
            }

            biggest = 0;

            foreach (ListViewItem li in hakList.Items)
            {
                if (li.Text.EndsWith("OFF"))
                {
                    li.ForeColor = Color.FromArgb(52, 152, 219);
              
                }
                else if (li.Text.EndsWith("ON"))
                {
                    li.ForeColor = Color.ForestGreen;
                  
                }
                else
                {
                    li.ForeColor = Color.FromArgb(52, 152, 219);
                }
                int thislength = li.Text.Length;
                if (thislength >= biggest) biggest = thislength;
            }

            int length = hakList.Items.Count;

            int mod = 21;

            if (length == 3)
                mod = 24;

            if (length == 2)
                mod = 29;

            if (length == 1)
                mod = 33;

            Size = new Size(biggest * 7, length * mod);
        }
        private void timer1_Tick(object sender, EventArgs e)
        {

        }

        private void timer2_Tick(object sender, EventArgs e)
        {

        }

        private void MakeTransparent(Control ctrl, int x, int y)
        {
            Bitmap bMap = new Bitmap(this.BackgroundImage);
            Color[,] pixelArray = new Color[ctrl.Width, ctrl.Height];

            for (int i = 0; i < ctrl.Width; i++)
            {
                for (int j = 0; j < ctrl.Height; j++)
                {
                    pixelArray[i, j] = bMap.GetPixel(x + i, y + j);
                }
            }

            Bitmap bmp = new Bitmap(ctrl.Width, ctrl.Height);

            for (int i = 0; i < ctrl.Width; i++)
            {
                for (int j = 0; j < ctrl.Height; j++)
                {
                    bmp.SetPixel(i, j, pixelArray[i, j]);
                }
            }

            ctrl.BackgroundImage = bmp;
            ctrl.Location = new Point(x, y);
        }
        private void button2_Click(object sender, EventArgs e)
        {

        }

        private void Keybind_Paint(object sender, PaintEventArgs e)
        {
           
        }

        private void hakList_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
