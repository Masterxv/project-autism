namespace pAutism
{
    partial class Keybind
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.button1 = new System.Windows.Forms.Button();
            this.hakList = new System.Windows.Forms.ListView();
            this.SuspendLayout();
            // 
            // button1
            // 
            this.button1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.ForeColor = System.Drawing.Color.White;
            this.button1.Location = new System.Drawing.Point(214, 0);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(19, 21);
            this.button1.TabIndex = 8;
            this.button1.Text = "X";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // hakList
            // 
            this.hakList.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(17)))), ((int)(((byte)(17)))), ((int)(((byte)(17)))));
            this.hakList.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.hakList.Dock = System.Windows.Forms.DockStyle.Fill;
            this.hakList.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.hakList.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(52)))), ((int)(((byte)(152)))), ((int)(((byte)(219)))));
            this.hakList.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.None;
            this.hakList.Location = new System.Drawing.Point(0, 0);
            this.hakList.MultiSelect = false;
            this.hakList.Name = "hakList";
            this.hakList.Size = new System.Drawing.Size(233, 388);
            this.hakList.TabIndex = 7;
            this.hakList.UseCompatibleStateImageBehavior = false;
            this.hakList.View = System.Windows.Forms.View.List;
            this.hakList.SelectedIndexChanged += new System.EventHandler(this.hakList_SelectedIndexChanged);
            this.hakList.MouseDown += new System.Windows.Forms.MouseEventHandler(this.hakList_MouseDown);
            this.hakList.MouseMove += new System.Windows.Forms.MouseEventHandler(this.hakList_MouseMove);
            this.hakList.MouseUp += new System.Windows.Forms.MouseEventHandler(this.hakList_MouseUp);
            // 
            // Keybind
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(17)))), ((int)(((byte)(17)))), ((int)(((byte)(17)))));
            this.ClientSize = new System.Drawing.Size(233, 388);
            this.ControlBox = false;
            this.Controls.Add(this.button1);
            this.Controls.Add(this.hakList);
            this.Font = new System.Drawing.Font("Segoe UI", 8.25F);
            this.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(52)))), ((int)(((byte)(152)))), ((int)(((byte)(219)))));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "Keybind";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.Text = "Keybind";
            this.TopMost = true;
            this.TransparencyKey = System.Drawing.Color.Transparent;
            this.Load += new System.EventHandler(this.Keybind_Load);
            this.Paint += new System.Windows.Forms.PaintEventHandler(this.Keybind_Paint);
            this.MouseDown += new System.Windows.Forms.MouseEventHandler(this.Keybind_MouseDown);
            this.MouseMove += new System.Windows.Forms.MouseEventHandler(this.Keybind_MouseMove);
            this.MouseUp += new System.Windows.Forms.MouseEventHandler(this.Keybind_MouseUp);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.ListView hakList;
        private System.Windows.Forms.Button button1;
    }
}