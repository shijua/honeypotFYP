window.NB_PORTAL_CONFIG = {
  apiBase: "/api/v1",
  invoiceEndpoint: "/api/v1/invoices",
  adminStatusEndpoint: "/admin/status",
  internalStatusEndpoint: "/internal-api/status",
  internalGitHost: "git.internal.local",
  internalDbHost: "db01.internal.local",
  internalRedisHost: "redis-cache.internal.local",
  legacyIntegration: {
    INTERNAL_API_KEY: "nb_api_ro_2026_04_status",
    GITEA_TOKEN: "nbg_git_ro_2026_04_legacy",
    BACKUP_READER_PASSWORD: "NbBackupReader-2026-04",
    PORTAL_READER_TOKEN: "nbp_reader_2026_04_window"
  }
};

document.addEventListener("submit", (event) => {
  if (event.target.matches("form[action='/api/v1/login']")) {
    event.preventDefault();
    window.location.hash = "login-failed";
  }
});

//# sourceMappingURL=/assets/app.js.map
