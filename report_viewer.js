document.addEventListener('DOMContentLoaded', async () => {
  try {
    const { vulnlens_last_report_html } = await browser.storage.local.get('vulnlens_last_report_html');
    if (vulnlens_last_report_html) {
      document.open();
      document.write(vulnlens_last_report_html);
      document.close();
    } else {
      document.body.textContent = 'Error: No report data found in storage.';
    }
  } catch (err) {
    document.body.textContent = `Error loading report: ${err.message}`;
  }
});
