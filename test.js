var browser = new ChromiumWebBrowser("https://www.google.com");
browser.Name = "Simple Page";
browser.Dock = DockStyle.Fill;            
this.Controls.Add(browser);
browser.ExecuteScriptAsync("alert('test');");