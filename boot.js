// Runs synchronously, before anything else below, so an encryption-locked
  // app shows the full-screen lock overlay immediately with no flash of the
  // (empty, but still structural) table UI behind it. See the
  // `html.locked-boot` rule in <style> and showUnlockOverlay()/hideUnlockOverlay()
  // in the main script, which keep this class in sync after boot.
  (function () {
    try {
      if (localStorage.getItem('budgetref-encryption-enabled') === 'true') {
        document.documentElement.classList.add('locked-boot');
      }
    } catch (e) {}
  })();
